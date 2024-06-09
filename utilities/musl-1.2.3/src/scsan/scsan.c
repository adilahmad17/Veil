#define _GNU_SOURCE
#include "scsan.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>
#include "scsan_malloc.h"

#include "syscall.h"
#include "veil.h"

extern bool enclave_execution;
long ocall_common(long sysno, long a1, long a2, long a3, long a4, long a5, long a6);

/* Global context */
context_t scsan_ctx;
bool scsan_ctx_init = false;
bool handle_scsan_syscall = false;
bool syscall_args_debug = false;

#define DEEPCOPY 1
#define PASSTHROUGH 1

#define fatal(s) {\
        perror((s));\
        exit(EXIT_FAILURE); }

int ctx_debug_log(context_t *ctx, const char *fmt, ...) {
        if (!ctx->debug) {
                return 0;
        }
        int ret = 0;
        va_list args;
        va_start(args, fmt);
        ret = vfprintf(stderr, fmt, args);
        va_end(args);
        return ret;
}

void *realloc_safe(void *a, size_t len) {
        void *aa = scsan_realloc(a, len);
        if (aa == NULL) {
                fatal("realloc");
        }
        return aa;
}

void *malloc_safe(size_t len) {
        void *aa = scsan_malloc(len);
        if (aa == NULL) {
                fatal("malloc");
        }

        /* Adil: memsetting to zero. */
        memset(aa, 0, len);
        return aa;
}

void membk_append(membk_t *mb, void *addr, size_t len) {
        if (mb->arr_len == mb->arr_cap) {
                ctx_debug_log(&scsan_ctx, "LEN=CAP (%d = %d)\n", mb->arr_len, mb->arr_cap);
                size_t new_arr_cap = mb->arr_cap << 1;
                mb->arr = realloc_safe(mb->arr, new_arr_cap*sizeof(membk_elem_t));
                mb->arr_cap = new_arr_cap;
        }
        mb->arr[mb->arr_len++] = (membk_elem_t){
                .addr = addr,
                .len = len
        };

        /* Adil: debugging membk appends */
        ctx_debug_log(&scsan_ctx, "membk append (idx: %d, %p, %ld)\n", 
                        mb->arr_len-1, mb->arr[mb->arr_len-1].addr, mb->arr[mb->arr_len-1].len);
}

membk_t membk_init() {
        size_t init_arr_cap = 32;
        ctx_debug_log(&scsan_ctx, "initializing membk\n");
        /*
        membk_t* n = malloc_safe(sizeof(membk_t));
        if (!n) fatal("membk allocation failed.\n");
        
        n->arr = malloc_safe(init_arr_cap*sizeof(membk_elem_t));
        n->arr_cap = init_arr_cap;
        n->arr_len = 0;
        return *n;
        */ 
        return (membk_t) {
                .arr = malloc_safe(init_arr_cap*sizeof(membk_elem_t)),
                .arr_cap = init_arr_cap,
                .arr_len = 0
        };
}

void membk_free(membk_t *mb) {
        scsan_free(mb->arr);
        mb->arr = NULL;
        mb->arr_cap = 0;
        mb->arr_len = 0;
}

typedef struct syscall_info {
        arg_id_type_t      arg_types[6];
} syscall_info_t;

arg_type_t* arg_spec_get_info(arg_spec_t *arg_spec, arg_id_type_t ty) {
        if (ty < 0 || ty > arg_spec->max_arg_type) {
                printf("invalid arg type %d, max arg type %d\n", ty, arg_spec->max_arg_type);
                exit(EXIT_FAILURE);
        }
        return &arg_spec->arg_info[ty];
}


void init_call_spec(spec_t *s, char *path) {
        FILE *f = fopen(path, "r");
        if (f == NULL) {
                perror("open call spec file");
                exit(EXIT_FAILURE);
        }

        long max_sysno = 0;
        int n_calls = 0;
        if (fscanf(f, "%ld%d", &max_sysno, &n_calls) != 2) {
               perror("read number of calls"); 
               exit(EXIT_FAILURE);
        }

        ctx_debug_log(&scsan_ctx,"Detail: Max system calls --> %d\n", max_sysno);
        s->max_sysno = max_sysno;
        s->syscall_spec = malloc_safe((max_sysno+1) * sizeof(syscall_spec_t));
        s->call_spec = malloc_safe(n_calls * sizeof(call_spec_t));
        for (int i = 0; i <= max_sysno; i++) {
                s->syscall_spec[i].unsupported = true;
                s->syscall_spec[i].cap_calls = 1;
                s->syscall_spec[i].n_calls = 0;
                s->syscall_spec[i].calls = malloc_safe(sizeof(int));
        }

        /* Adil */
        int index = 1;
        for (int i = 0; i < n_calls; i++) {
                long sysno;
                int n_arg;
                fscanf(f, "%ld %d", &sysno, &n_arg);
                syscall_spec_t *sc = &s->syscall_spec[sysno];

                /* Adil */
                ctx_debug_log(&scsan_ctx, "Detail: (%d) Supported system call --> %d\n",  index++, sysno);
                sc->unsupported = false;
                s->call_spec[i].n_arg = n_arg;
                s->call_spec[i].args = malloc_safe(n_arg * sizeof(arg_id_type_t));
                for (int j = 0; j < n_arg; j++) {
                        fscanf(f, "%d", &s->call_spec[i].args[j]);
                }
                fscanf(f, "%d %d", &s->call_spec[i].branch_arg, &s->call_spec[i].n_branch_arg_vals);
                if (s->call_spec[i].n_branch_arg_vals != 0) {
                        s->call_spec[i].branch_arg_vals = malloc_safe(s->call_spec[i].n_branch_arg_vals * sizeof(long)); 
                        for (int j = 0; j < s->call_spec[i].n_branch_arg_vals; j++) {
                                fscanf(f, "%ld", &s->call_spec[i].branch_arg_vals[j]);
                        }
                } else {
                        s->call_spec[i].branch_arg_vals = NULL;
                }
                if (sc->cap_calls == sc->n_calls) {
                        sc->cap_calls <<= 1;
                        sc->calls = realloc_safe(sc->calls, sc->cap_calls * sizeof(int));
                }
                sc->calls[sc->n_calls++] = i;
        }
        fclose(f);
}

void init_arg_spec(spec_t *s, char *path) {
        FILE *f = fopen(path, "r");
        if (f == NULL) {
                perror("open arg spec file");
                exit(EXIT_FAILURE);
        }

        int n_args = 0;
        if (fscanf(f, "%d", &n_args) != 1) {
               perror("read number of args"); 
               exit(EXIT_FAILURE);
        }
        s->arg_spec.arg_info = malloc_safe(n_args * sizeof(arg_type_t));
        s->arg_spec.max_arg_type = n_args;
        arg_id_type_t id;
        int ty;
        for (int i = 0; i < n_args; i++) {
                if (fscanf(f, "%d %d", &id, &ty) != 2) {
                        perror("read id and types"); 
                        exit(EXIT_FAILURE);
                }
                s->arg_spec.arg_info[i].base.id = id;
                s->arg_spec.arg_info[i].base.type = ty;
                switch (ty) {
                case SCALAR_TYPE:
                {
                        size_t len = 0; 
                        fscanf(f, "%ld", &len);
                        s->arg_spec.arg_info[i].scalar.len = len;
                        break;
                }
                case ARRAY_TYPE:
                {
                        array_type_t arr;
                        int is_var_len_int = 0;
                        fscanf(f, "%d %d %d %d", &is_var_len_int, &arr.static_len, &arr.dyn_len_arg, &arr.elem);
                        arr.is_var_len = (is_var_len_int == 1);
                        fscanf(f, "%d", &arr.dyn_len_arg_path_size);
                        if (arr.dyn_len_arg_path_size != 0) {
                                arr.dyn_len_arg_path = malloc_safe(arr.dyn_len_arg_path_size * sizeof(arg_id_type_t));
                        }
                        for (int j = 0; j < arr.dyn_len_arg_path_size; j++) {
                                fscanf(f, "%d", &arr.dyn_len_arg_path[j]);
                        }
                        s->arg_spec.arg_info[i].array = arr;
                        break;
                }
                case BUFFER_TYPE:
                {
                        buffer_type_t buf;
                        int is_var_len_int = 0;
                        fscanf(f, "%d %d %d", &is_var_len_int, &buf.static_len, &buf.dyn_len_arg);
                        buf.is_var_len = (is_var_len_int == 1);
                        fscanf(f, "%d", &buf.dyn_len_arg_path_size);
                        if (buf.dyn_len_arg_path_size != 0) {
                                buf.dyn_len_arg_path = malloc_safe(buf.dyn_len_arg_path_size * sizeof(arg_id_type_t));
                        }
                        for (int j = 0; j < buf.dyn_len_arg_path_size; j++) {
                                fscanf(f, "%d", &buf.dyn_len_arg_path[j]);
                        }
                        s->arg_spec.arg_info[i].buffer = buf;
                        break;
                }
                case STRUCT_TYPE:
                {
                        struct_type_t strct;
                        int is_var_len_int = 0;
                        fscanf(f, "%d %d %d %d", &strct.n_fields, &is_var_len_int, &strct.static_len, &strct.dyn_len_arg);
                        strct.is_var_len = (is_var_len_int == 1);
                        s->arg_spec.arg_info[i].strct = strct;
                        s->arg_spec.arg_info[i].strct.fields = malloc_safe(strct.n_fields * sizeof(struct_field_type_t));
                        for (int j = 0; j < strct.n_fields; j++) {
                                fscanf(f, "%d %d",
                                        &s->arg_spec.arg_info[i].strct.fields[j].field,
                                        &s->arg_spec.arg_info[i].strct.fields[j].offset
                                );
                        }
                        fscanf(f, "%d", &s->arg_spec.arg_info[i].strct.dyn_len_arg_path_size);
                        if (s->arg_spec.arg_info[i].strct.dyn_len_arg_path_size != 0) {
                                s->arg_spec.arg_info[i].strct.dyn_len_arg_path = malloc_safe(s->arg_spec.arg_info[i].strct.dyn_len_arg_path_size * sizeof(arg_id_type_t));
                        }
                        for (int j = 0; j < s->arg_spec.arg_info[i].strct.dyn_len_arg_path_size; j++) {
                                fscanf(f, "%d", &s->arg_spec.arg_info[i].strct.dyn_len_arg_path[j]);
                        }
                        break;
                }
                case POINTER_TYPE:
                {
                        pointer_type_t ptr;
                        fscanf(f, "%d %d", &ptr.pointee, &ptr.dir);
                        s->arg_spec.arg_info[i].pointer = ptr;
                        break;
                }
                case LEN_TYPE:
                {
                        len_type_t len;
                        fscanf(f, "%d %d", &len.len, &len.bit_size);
                        s->arg_spec.arg_info[i].len = len;
                        break;
                }

                }
        }
        fclose(f);
}

void init_scsan_malloc() {
        size_t size = 1 << 30;
        void *a = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
        if (a == MAP_FAILED) {
                perror("mmap");
        }
        scsan_malloc_init(a, size);
}

void init_spec(spec_t *s) {
        char *call_spec_path = getenv("SCSAN_CALL_SPEC");
        if (call_spec_path == NULL) {
                printf("no SCSAN_CALL_SPEC specified");
                exit(EXIT_FAILURE);
        }
        init_call_spec(s, call_spec_path);
        char *arg_spec_path = getenv("SCSAN_ARG_SPEC");
        if (arg_spec_path == NULL) {
                printf("no SCSAN_ARG_SPEC specified");
                exit(EXIT_FAILURE);
        }
        init_arg_spec(s, arg_spec_path);
}

void init_context(context_t *ctx, spec_t *spec) {
        ctx->spec = spec;
        ctx->mb = membk_init();
        if (getenv("SCSAN_DEBUG")) {
                ctx->debug = true;
        } else {
                ctx->debug = false;
        }
}

/* Adil: always print debug statements. */
int scsan_debug(const char *fmt, ...) {
        int ret = 0;
        va_list args;
        va_start(args, fmt);
        ret = vfprintf(stderr, fmt, args);
        va_end(args);
        return ret;
}

void *ctx_alloc_safe(context_t *ctx, size_t len) {
        void *addr = malloc_safe(len);
        /* Adil: sanity check added. */
        if (!addr) 
                fatal("ctx_alloc_safe failed.");
        
        memset(addr, 0, len);
        membk_append(&ctx->mb, addr, len);
        return addr;
}

void ctx_free_copied_mem(context_t *ctx) {
        membk_t *mb = &ctx->mb;
        /* Adil: sanity check added. */
        if (!mb) return;

        // ctx_debug_log(ctx, "freeing entries (arr_len = %d)\n", mb->arr_len);
        for (int i = 0; i < mb->arr_len; i++) {
                /* Adil: sanity check(s) added. */
                if (&(mb->arr[i])) {
                        if (mb->arr[i].addr != NULL) {
                                ctx_debug_log(ctx, "idx %d, freeing %p\n", i, mb->arr[i].addr);
                                scsan_free(mb->arr[i].addr);
                        }
                }
        }

        ctx_debug_log(ctx, "freeing membk\n");
        membk_free(mb);
        return;
}

void context_free(context_t *ctx) {
        ctx_free_copied_mem(ctx);
}

arg_type_t* ctx_get_arg_info(context_t *ctx, arg_id_type_t ty) {
        return arg_spec_get_info(&ctx->spec->arg_spec, ty);
}

call_spec_t* ctx_get_call_info(context_t *ctx, intptr_t sysno, intptr_t args[]) {
        if (sysno > ctx->spec->max_sysno || sysno < 0) {
                scsan_debug("invalid syscall number %ld, max %ld\n", sysno, ctx->spec->max_sysno);
                exit(EXIT_FAILURE);
        }
        syscall_spec_t *s = &ctx->spec->syscall_spec[sysno];
        if (s->unsupported == true) {
                ctx_debug_log(&scsan_ctx, "Detail: Unsupported system call.\n");
                return NULL;
        }
        for (int i = 0; i < s->n_calls; i++) {
                call_spec_t *c = &ctx->spec->call_spec[s->calls[i]];
                if (c->branch_arg == -1) {
                        return c;
                } else {
                        for (int j = 0; j < c->n_branch_arg_vals; j++) {
                                if (c->branch_arg_vals[j] == args[c->branch_arg]) {
                                        return c;
                                }
                        }
                }
        }
        return NULL;
}


typedef struct scsan_arg_info {
        void*           addr;
        arg_id_type_t   id;
}scsan_arg_info_t;

typedef struct scsan_arg_stack {
        scsan_arg_info_t*               call_args;
        int                             n_call_arg;
        scsan_arg_info_t*               stack;
        size_t                          cap;
        size_t                          size;
}scsan_arg_stack_t;

void scsan_arg_stack_init(scsan_arg_stack_t *s, int n_call_args, arg_id_type_t *ca, intptr_t *val) {
        int cap = 32;
        s->stack = malloc_safe(cap * sizeof(scsan_arg_info_t));
        s->cap = cap;
        s->size = 0;
        s->call_args = malloc_safe(n_call_args * sizeof(scsan_arg_info_t));
        for (int i = 0; i < n_call_args; i++) {
                s->call_args[i].id = ca[i];
                s->call_args[i].addr = (void *)(&val[i]);
        }
        s->n_call_arg = n_call_args;
}

void scsan_arg_stack_init_from(scsan_arg_stack_t *s, scsan_arg_stack_t *src) {
        s->stack = malloc_safe(src->cap * sizeof(scsan_arg_info_t));
        memcpy(s->stack, src->stack, src->cap * sizeof(scsan_arg_info_t));
        s->call_args = malloc_safe(src->n_call_arg * sizeof(scsan_arg_info_t));
        memcpy(s->call_args, src->call_args, src->n_call_arg * sizeof(scsan_arg_info_t));
        s->n_call_arg = src->n_call_arg;
        s->cap = src->cap;
        s->size = src->size;
}

void scsan_arg_stack_free(scsan_arg_stack_t *s) {
        scsan_free(s->stack);
        scsan_free(s->call_args);
        s->stack = NULL;
        s->cap = s->size = s->n_call_arg = 0;
        s->call_args = NULL;
}

scsan_arg_info_t scsan_arg_stack_top(scsan_arg_stack_t *s) {
        if (s->size == 0) {
                printf("cannot get top for empty stack");
                exit(EXIT_FAILURE);
        }
        return s->stack[s->size-1];
}

size_t scsan_arg_stack_size(scsan_arg_stack_t *s) {
        return s->size;
}

scsan_arg_info_t scsan_arg_stack_pop(scsan_arg_stack_t *s) {
        if (s->size == 0) {
                printf("cannot pop empty stack");
                exit(EXIT_FAILURE);
        }
        return s->stack[--(s->size)];
}

void scsan_arg_stack_push(scsan_arg_stack_t *s, scsan_arg_info_t f) {
        if (s->size == s->cap) {
                s->cap <<= 1;
                s->stack = realloc_safe(s->stack, s->cap * sizeof(scsan_arg_info_t));
        }
        s->stack[s->size++] = f;
}

size_t get_len_arg_val(context_t *ctx, scsan_arg_stack_t *s, arg_id_type_t* path, int path_len) {
        if (path_len == 0) {
                scsan_arg_info_t f = scsan_arg_stack_top(s);
                arg_type_t *info = ctx_get_arg_info(ctx, f.id);
                if (info->base.type != LEN_TYPE) {
                        fprintf(stderr, "resolve to type that is not len");
                        exit(EXIT_FAILURE);
                }
                size_t val;
                switch (info->len.len) {
                case 1:
                        val = (size_t)(*(uint8_t*)f.addr);
                        break;
                case 2:
                        val = (size_t)(*(uint16_t*)f.addr);
                        break;
                case 4:
                        val = (size_t)(*(uint32_t*)f.addr);
                        break;
                case 8:
                        val = (size_t)(*(uint64_t*)f.addr);
                        break;
                default:
                        printf("invalid length variable bytes number %d",
                        info->len.len);
                        exit(EXIT_FAILURE);
                }
                return val;
        }
        if (path[0] == -1) {
                scsan_arg_stack_pop(s);
                return get_len_arg_val(ctx, s, path+1, path_len-1);
        } else if (path[0] == -2) {
                while(scsan_arg_stack_size(s) != 0) {
                        scsan_arg_stack_pop(s);
                }
                return get_len_arg_val(ctx, s, path+1, path_len-1);
        } else {
                bool find = false;
                scsan_arg_info_t next;

                if (scsan_arg_stack_size(s) == 0) {
                        // We are at call level.
                        for (int i = 0; i < s->n_call_arg; i++) {
                                // automatically dereference the pointer
                                // TODO: do we need to apply the same fix to below?
                                arg_type_t *a = &ctx->spec->arg_spec.arg_info[s->call_args[i].id];
                                arg_id_type_t id = a->base.id;
                                void *addr = s->call_args[i].addr;
                                if (a->base.type == POINTER_TYPE) {
                                        id = a->pointer.pointee;
                                        if (id == path[0]) {
                                                if (addr == NULL) {
                                                        fprintf(stderr, "len %d is in a NULL pointer!\n", id);
                                                        exit(EXIT_FAILURE);
                                                } else {
                                                        addr = *(void **)addr;
                                                }
                                        }
                                }
                                if (id == path[0]) {
                                        find = true;
                                        next = (scsan_arg_info_t){.id = id, .addr = addr};
                                        break;
                                }
                        }
                } else {
                        scsan_arg_info_t now = scsan_arg_stack_top(s);
                        arg_type_t *info = ctx_get_arg_info(ctx, now.id);
                        switch(info->base.type) {
                        case STRUCT_TYPE:
                        {       
                                struct_type_t strct = info->strct;
                                for (int i = 0; i < strct.n_fields; i++) {
                                        if (strct.fields[i].field == path[0]) {
                                                find = true;
                                                next = (scsan_arg_info_t) {
                                                        // Adil: suppressed pointer arithmetic by type-casting to uint64 and again to void*
                                                        .addr = (void*) ((uint64_t) now.addr + strct.fields[i].offset),
                                                        .id = path[0]
                                                };
                                                break;
                                        }
                                }
                                break;
                        }
                        case POINTER_TYPE:
                        {
                                pointer_type_t ptr = info->pointer;
                                if (ptr.pointee == path[0]) {
                                        next = (scsan_arg_info_t) {
                                                .addr = *(void **)now.addr,
                                                .id = path[0]
                                        };
                                        find = true;
                                }
                                break;
                        }
                        default:
                                break;
                        }
                }

                if (find) {
                        scsan_arg_stack_push(s, next);
                        size_t size = get_len_arg_val(ctx, s, path+1, path_len-1);
                        scsan_arg_stack_pop(s);
                        return size;
                } else {
                        printf("cannot find id %d", path[0]);
                        exit(EXIT_FAILURE);
                }
        }

}

size_t ctx_get_len_arg_val(context_t *ctx, scsan_arg_stack_t *s, arg_id_type_t* path, int path_len) {
        scsan_arg_stack_t cs;
        scsan_arg_stack_init_from(&cs, s);
        size_t len_arg_val = get_len_arg_val(ctx, &cs, path, path_len);
        scsan_arg_stack_free(&cs);
        return len_arg_val;
}

// This will change SCSAN arg stack s.
size_t arg_size(context_t *ctx, scsan_arg_stack_t *s, void *arg, arg_id_type_t ty) {

        arg_type_t* info = ctx_get_arg_info(ctx, ty);
        switch (info->base.type) {
        case ARRAY_TYPE:
        {
                array_type_t arr = info->array;
                bool is_total_size = false;
                size_t total_size = 0, n_elem = 0;
                
                if (arr.is_var_len) {
                        len_type_t len_arg = ctx_get_arg_info(ctx, arr.dyn_len_arg)->len;
                        size_t len_arg_val = get_len_arg_val(ctx, s, arr.dyn_len_arg_path, arr.dyn_len_arg_path_size);
                        is_total_size = len_arg.bit_size != 0;
                        if (is_total_size) {
                                total_size = len_arg_val * 8 / len_arg.bit_size;
                        } else {
                                n_elem = len_arg_val;
                        }
                } else {
                        n_elem = arr.static_len;
                }
                
                if (!is_total_size) {
                        for (int i = 0; i < n_elem; i++) {
                                // TODO: think about what if we crash or infinite loop? 
                                // This could be slow, but it scales to dynamic struct elements.
                                // Adil: uint64 -> void* 
                                scsan_arg_stack_push(s, (scsan_arg_info_t){.addr = (void*) ((uint64_t)arg + total_size), .id = arr.elem});
                                total_size += arg_size(ctx, s, (void*) ((uint64_t)arg + total_size), arr.elem);
                                scsan_arg_stack_pop(s);
                        }
                }
                return total_size;
        }
        case BUFFER_TYPE:
        {
                buffer_type_t buf = info->buffer;
                size_t size = 0;
                if (buf.is_var_len) {
                        if (buf.dyn_len_arg == -2) {
                                size = strlen(arg)+1;
                        } else {
                                size = get_len_arg_val(ctx, s, buf.dyn_len_arg_path, buf.dyn_len_arg_path_size);
                        }
                } else {
                        size = buf.static_len;
                }
                return size;
        }
        case SCALAR_TYPE:
                return info->scalar.len;
        case STRUCT_TYPE:
        {
                struct_type_t strct = info->strct;
                size_t size = 0;
                if (strct.is_var_len) {
                        size = get_len_arg_val(ctx, s, strct.dyn_len_arg_path, strct.dyn_len_arg_path_size);
                } else {
                        size = strct.static_len;
                }
                return size;
        }
        case POINTER_TYPE:
        {
                return sizeof(void *);
        }
        case LEN_TYPE:
        {
                return info->len.len;
        }
        default:
                printf("unhandled type\n");
                exit(EXIT_FAILURE);

        }
}

size_t ctx_get_arg_size(context_t *ctx, scsan_arg_stack_t *s, void *arg, arg_id_type_t ty) {
        scsan_arg_stack_t cs;
        scsan_arg_stack_init_from(&cs, s);
        size_t size = arg_size(ctx, &cs, arg, ty);
        scsan_arg_stack_free(&cs);
        return size;
}

void* deep_copy_arg(context_t *ctx, scsan_arg_stack_t *s, void *src_arg, arg_id_type_t ty, void *dst_arg, size_t *size, bool syscall_entry, bool copy_this);

void* deep_copy_arg_with_stack_update(context_t *ctx, scsan_arg_stack_t *s, void *src_arg, arg_id_type_t ty, void *dst_arg, size_t *size, bool syscall_entry, bool copy_this) {
        scsan_arg_stack_push(s, (scsan_arg_info_t){.addr = src_arg, .id = ty});
        void *ret = deep_copy_arg(ctx, s, src_arg, ty, dst_arg, size, syscall_entry, copy_this);
        scsan_arg_stack_pop(s);
        return ret;
}

void* deep_copy_arg(context_t *ctx, scsan_arg_stack_t *s, void *src_arg, arg_id_type_t ty, void *dst_arg, size_t *size, bool syscall_entry, bool copy_this) {
        /* ctx_debug_log(ctx, "arg = %p, type = %d\n", src_arg, ty); */
        if (src_arg == NULL) {
                return NULL;
        }
        arg_type_t* info = ctx_get_arg_info(ctx, ty);
        size_t copied_size = ctx_get_arg_size(ctx, s, src_arg, ty);
        /* ctx_debug_log(ctx, "arg size = %d\n", copied_size); */
        if (dst_arg == NULL) {
                dst_arg = ctx_alloc_safe(ctx, copied_size);
        }
        switch (info->base.type) {
        case ARRAY_TYPE:
        {
                ctx_debug_log(ctx, "[ARRAY] src = %p, size = %d, dst = %p\n", src_arg, copied_size, dst_arg);
                array_type_t arr = info->array;
                size_t cur_copied_size = 0;
                while (cur_copied_size < copied_size) {
                        // copy the element one by one.
                        size_t size = 0;
                        // Adil: again suppressed
                        deep_copy_arg_with_stack_update(ctx, s, (void*) ((uint64_t)src_arg+cur_copied_size), arr.elem, (void*) ((uint64_t)dst_arg+cur_copied_size), &size, syscall_entry, copy_this);
                        cur_copied_size += size;
                        ctx_debug_log(ctx, "array type %d, copied %d/%d bytes...\n", ty, cur_copied_size, copied_size);
                }
                if (cur_copied_size > copied_size) {
                        // panic: should be equal
                        printf("copy array: total size = %ld, copied size = %ld\n", copied_size, cur_copied_size);
                        exit(EXIT_FAILURE);
                }
                break;
        }
        case STRUCT_TYPE:
        {
                ctx_debug_log(ctx, "[STRUCT] src = %p, size = %d, dst = %p\n", src_arg, copied_size, dst_arg);
                struct_type_t strct = info->strct;
                if (copy_this) {
                        memcpy(dst_arg, src_arg, copied_size);
                }
                for (int i = 0 ; i < strct.n_fields; i++) {
                        struct_field_type_t f = strct.fields[i];
                        ctx_debug_log(ctx, "in struct type %d, now go into field %d\n", ty, f.field);
                        // Adil: kept original for checking
                        /* deep_copy_arg_with_stack_update(ctx, s, src_arg+f.offset, f.field, dst_arg+f.offset, NULL, syscall_entry); */ 
                        deep_copy_arg_with_stack_update(ctx, s, (void*) ((uint64_t)src_arg+f.offset), f.field, (void*) ((uint64_t)dst_arg+f.offset), NULL, syscall_entry, copy_this);
                }
                break;
        }
        case POINTER_TYPE:
        {
                ctx_debug_log(ctx, "[POINTER] src = %p, size = %d, dst = %p\n", src_arg, copied_size, dst_arg);
                pointer_type_t ptr = info->pointer;
                if (syscall_entry) {
                        *(void**)dst_arg = deep_copy_arg_with_stack_update(ctx, s, *(void**)src_arg, ptr.pointee, NULL, NULL, syscall_entry, copy_this);
                } else {
                        arg_type_t *pointee = ctx_get_arg_info(ctx, ptr.pointee);
                        ctx_debug_log(ctx, "on exit visit pointer...");
                        // NOTE: Do we need to copy back pointer address?
                        // If kernel specifies a address for user space to look at, then this can cause bugs.
                        // Keep this in mind.
                        deep_copy_arg_with_stack_update(ctx, s, *(void**)src_arg, ptr.pointee, *(void**)dst_arg, NULL, syscall_entry, ptr.dir != IN_DIR);
                }
                break;
        }
        case LEN_TYPE:
                ctx_debug_log(ctx, "[LEN] src = %p, size = %d, dst = %p\n", src_arg, copied_size, dst_arg);
                if (copy_this) {
                        memcpy(dst_arg, src_arg, copied_size);
                }
                break;
        case BUFFER_TYPE:
                ctx_debug_log(ctx, "[BUFFER] src = %p, size = %d, dst = %p\n", src_arg, copied_size, dst_arg);
                if (copy_this) {
                        memcpy(dst_arg, src_arg, copied_size);
                }
                break;
        case SCALAR_TYPE:
                ctx_debug_log(ctx, "[SCALAR] src = %p, size = %d, dst = %p\n", src_arg, copied_size, dst_arg);
                if (copy_this) {
                        memcpy(dst_arg, src_arg, copied_size);
                }
                // scsan_debug("copied value = %d\n", *((int*) src_arg));
                // scsan_debug("copied value = %d\n", *((int*) dst_arg));
                break;
        }
        if (size != NULL) {
                *size = copied_size;
        }
        return dst_arg;
}

typedef void syscall_deep_copy_special_handler(context_t*, intptr_t[], intptr_t[], bool);

char* deep_copy_helper_new_string(context_t *ctx, char *src) {
        if (src == NULL) {
                return NULL;
        }
        // change to size_t
        int l = strlen(src);
        char *dst = ctx_alloc_safe(ctx, l+1);
        strcpy(dst, src);
        return dst;
}

char** deep_copy_new_execve_double_array(context_t *ctx, char **src) {
        if (src == NULL) {
                return NULL;
        }
        int l = 0;
        while(src[l++] != NULL);
        char **dst = ctx_alloc_safe(ctx, l * sizeof(char *));
        for (int i = 0; i < l; i++) {
                dst[i] = deep_copy_helper_new_string(ctx, src[i]);
        }
        return dst;
}

void deep_copy_execve(context_t *ctx, intptr_t args[], intptr_t new_args[], bool syscall_entry) {
        if (syscall_entry) {
                new_args[0] = (intptr_t)deep_copy_helper_new_string(ctx, (char *)args[0]);
                new_args[1] = (intptr_t)deep_copy_new_execve_double_array(ctx, (char **)args[1]);
                new_args[2] = (intptr_t)deep_copy_new_execve_double_array(ctx, (char **)args[2]);
        }
}

syscall_deep_copy_special_handler* syscall_special_handlers[1024] = {
        [SYS_execve] = &deep_copy_execve,
};

static __inline long __scsan_syscall6(long n, long a1, long a2, long a3, long a4, long a5, long a6)
{
	unsigned long ret;
	register long r10 __asm__("r10") = a4;
	register long r8 __asm__("r8") = a5;
	register long r9 __asm__("r9") = a6;
	__asm__ __volatile__ ("syscall" : "=a"(ret) : "a"(n), "D"(a1), "S"(a2),
						  "d"(a3), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return ret;
}

/* Adil: debugging purposes.*/
extern unsigned long syscall_total;
extern bool syscall_file_debug;
extern int syscall_debug_fd;

/* Adil: Removed context here, since it is being initialized once within 
 * the function __libc_start_main(..). */
uintptr_t scsan_syscall(intptr_t sysno, intptr_t args[], int arglen) {
        context_t* ctx = &scsan_ctx;
        handle_scsan_syscall = true;

        /* Tracking system calls using files. */
        if (syscall_file_debug) write(syscall_debug_fd, "syscall.\n", 10);

        // Track all system calls
        syscall_total++;

        // ctx_debug_log(ctx, "\nSCSAN_SYSCALL: handling syscall (%d)\n", sysno); 
        // scsan_debug("\nSCSAN_SYSCALL: handling syscall (%d)\n", sysno);

        // TODO: How to check invalid memory access?
        //      We can check NULL pointer.
        intptr_t new_args[6];
        long ret = 0;
        if (syscall_special_handlers[sysno] != NULL) {
                syscall_special_handlers[sysno](ctx, args, new_args, true);
                printf("SPECIAL syscall(%ld) {%lx, %lx, %lx, %lx, %lx, %lx}\n", 
                        sysno, new_args[0], new_args[1], new_args[2],
                        new_args[3], new_args[4], new_args[5]);
                // ret = syscall(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
                ret = __scsan_syscall6(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
                syscall_special_handlers[sysno](ctx, new_args, args, false);
                ctx_free_copied_mem(ctx);
                scsan_debug("DETAIL: Special system call.\n");
                handle_scsan_syscall = false;
                return ret;
        } 

        call_spec_t* call = ctx_get_call_info(ctx, sysno, args);
        if (call == NULL) {
#if PASSTHROUGH==1
                /* Implementing passthrough for simple testing. */
                int arr_len = arglen;
                ctx_debug_log(ctx, "Passthrough (array len = %d)\n", arr_len);
                printf("Passthrough syscall(%ld) {%lx, %lx, %lx, %lx, %lx, %lx}\n", 
                        sysno, new_args[0], new_args[1], new_args[2],
                        new_args[3], new_args[4], new_args[5]);
                for (int i = 0; i < arr_len; i++) {
                        new_args[i] = args[i];
                }
                for (int i = arr_len; i < 6; i++) {
                        new_args[i] = 0;
                }
                ret = __scsan_syscall6(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
                handle_scsan_syscall = false;
                return ret;
#else
                /* Adil: Changed to panic here. */
                fatal("Unsupported System Call");
                return -ENOSYS;
#endif
        
        }

#if DEEPCOPY==0
        /* Sample test without deep copy */
        for (int i = 0; i < call->n_arg; i++) {
                new_args[i] = args[i];
        }
        for (int i = call->n_arg; i < 6; i++) {
                new_args[i] = 0;
        }

        /* Bad way to solve the problem. (FIX) */
        if (enclave_execution == false) {
                if (syscall_args_debug && sysno != __NR_writev) {
                        printf("syscall(%ld) {%lx, %lx, %lx, %lx, %lx, %lx}", 
                        sysno, new_args[0], new_args[1], new_args[2],
                        new_args[3], new_args[4], new_args[5]);
                }
                ret = __scsan_syscall6(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
                if (syscall_args_debug && sysno != __NR_writev) {
                        printf(" --> %lx\n", ret);
                }
        } else {
                /* This works but the OCALL gives a segfault? */
                // ret = __scsan_syscall6(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
                
                ret = ocall_common(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
        }
#else
        /* Adil: Reinitialize the membk once? */
        ctx->mb = membk_init();

        scsan_arg_stack_t s;
        scsan_arg_stack_init(&s, call->n_arg, call->args, args);
        
        ctx_debug_log(ctx, "Call arguments: %d\n", call->n_arg);
        for (int i = 0; i < call->n_arg; i++) {
                deep_copy_arg_with_stack_update(ctx, &s, &args[i], call->args[i], &new_args[i], NULL, true, true);
        }
        // ret = syscall(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);

        /* Adil: changed this to route through custom syscall invokation. */
        if (enclave_execution == false) {
                if (syscall_args_debug && sysno != __NR_writev) {
                        printf("Non-enclave: syscall(%ld) {%lx, %lx, %lx, %lx, %lx, %lx}", 
                        sysno, new_args[0], new_args[1], new_args[2],
                        new_args[3], new_args[4], new_args[5]);
                }
                ret = __scsan_syscall6(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
                if (syscall_args_debug && sysno != __NR_writev) {
                        printf(" --> %lx\n", ret);
                }
        } else {
                ret = ocall_common(sysno, new_args[0], new_args[1], new_args[2], new_args[3], new_args[4], new_args[5]);
        }
        scsan_arg_stack_free(&s);
        scsan_arg_stack_init(&s, call->n_arg, call->args, new_args);
        
        // TODO: provide a handler to handle return value translation.
        for (int i = 0; i < call->n_arg; i++) {
                deep_copy_arg_with_stack_update(ctx, &s, &new_args[i], call->args[i], &args[i], NULL, false, false);
        }

        ctx_debug_log(ctx, "Freeing copied memory.\n");
        ctx_free_copied_mem(ctx);

        ctx_debug_log(ctx, "Freeing arg stack.\n");
        scsan_arg_stack_free(&s);
#endif

        handle_scsan_syscall = false;
        return ret;
}