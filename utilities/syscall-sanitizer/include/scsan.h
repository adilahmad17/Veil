#ifndef __SCSAN_H
#define __SCSAN_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef int arg_id_type_t;

typedef enum arg_type_enum {
        SCALAR_TYPE,
        ARRAY_TYPE,
        BUFFER_TYPE,
        STRUCT_TYPE,
        POINTER_TYPE,
        LEN_TYPE,
}arg_type_enum_t;

typedef enum arg_dir_enum {
        IN_DIR,
        OUT_DIR,
        INOUT_DIR,
}arg_dir_enum_t;

typedef struct type_base {
        arg_id_type_t      id;
        arg_type_enum_t    type;
}type_base_t;

typedef struct pointer_type {
        arg_id_type_t   pointee;
        int             dir;
}pointer_type_t;

typedef struct struct_field_type {
        arg_id_type_t   field;
        int             offset;
}struct_field_type_t;

typedef struct struct_type {
        int                     n_fields;
        bool                    is_var_len;
        int                     static_len;
        arg_id_type_t           dyn_len_arg;
        struct_field_type_t*    fields;
        int                     dyn_len_arg_path_size;
        arg_id_type_t*          dyn_len_arg_path;
}struct_type_t;

typedef struct buffer_type {
        bool                    is_var_len;
        int                     static_len;
        arg_id_type_t           dyn_len_arg;
        int                     dyn_len_arg_path_size;
        arg_id_type_t*          dyn_len_arg_path;
}buffer_type_t;

typedef struct array_type {
        bool                    is_var_len;
        int                     static_len;
        arg_id_type_t           dyn_len_arg;
        arg_id_type_t           elem;
        int                     dyn_len_arg_path_size;
        arg_id_type_t*          dyn_len_arg_path;
}array_type_t;

typedef struct scalar_type {
        int             len;
}scalar_type_t;


typedef struct len_type {
        int             len;
        int             bit_size;
}len_type_t;

typedef struct arg_type {
        type_base_t             base;
        union {
               scalar_type_t    scalar; 
               array_type_t     array;
               buffer_type_t    buffer;
               struct_type_t    strct;
               pointer_type_t   pointer;
               len_type_t       len;
        };
}arg_type_t;

typedef struct arg_spec {
        arg_type_t*     arg_info;
        arg_id_type_t   max_arg_type;
}arg_spec_t;

typedef struct call_spec {
        arg_id_type_t*  args;
        int             n_arg;
        int             branch_arg;
        int             n_branch_arg_vals;
        long*           branch_arg_vals;
}call_spec_t;

typedef struct syscall_spec {
        int*            calls;
        int             n_calls;
        int             cap_calls;
        bool            unsupported;
} syscall_spec_t;

typedef struct spec {
        arg_spec_t              arg_spec;
        syscall_spec_t*         syscall_spec;
        call_spec_t*            call_spec;
        intptr_t                max_sysno;
}spec_t;

typedef struct membk_elem {
        void    *addr;
        size_t  len;
}membk_elem_t;

typedef struct membk {
        membk_elem_t*   arr;
        size_t          arr_cap;
        size_t          arr_len;
}membk_t;

typedef struct context {
        membk_t                 mb;
        spec_t*                 spec;
        bool                    debug;
}context_t;

typedef void* alloc_func_t(size_t);
uintptr_t scsan_syscall(context_t *ctx, intptr_t sysno, intptr_t args[]);
void init_spec(spec_t *s);
void init_context(context_t *ctx, spec_t *spec);
void context_free(context_t *ctx);
#endif