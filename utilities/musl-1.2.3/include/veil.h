#ifndef __VEIL_H__
#define __VEIL_H__

#if 0
#include <stddef.h>
#include <stdint.h>

typedef uint8_t    u8;
typedef uint16_t   u16;
typedef uint32_t   u32;
typedef uint64_t   u64;

// This function should be defined in every application
extern unsigned long enclave_main_addr;
extern bool enclave_execution;
extern bool enclave_exited;

// Architectural values included by AMD for SEV
#define MSR_AMD64_SEV_ES_GHCB		    0xc0010130

#define SVM_VMGEXIT_VEIL					0x1230

/* New definitions (also re-defined in kvm.c of the host) 
 * Note: definitions in host and guest should be the same
 * for the communication to succeed. */
#define SVM_VMGEXIT_CREATE_SECMON           0x1234
#define SVM_VMGEXIT_SWITCH_TO_SECMON        0x1235
#define SVM_VMGEXIT_SWITCH_TO_OS 	        0x1236
#define SVM_VMGEXIT_DEPRIV_OS 	            0x1237
#define SVM_VMGEXIT_CREATE_ENCLAVE	 	    0x1238
#define SVM_VMGEXIT_SWITCH_TO_ENCLAVE	    0x1239

/* VMEXITs defined for debugging purposes only */
#define SVM_VMGEXIT_VEIL_DEBUG				0x1250
#define SVM_VMGEXIT_DUMP_VMCB				0x1251

#define	VMGEXIT()			{ __asm__ __volatile__ ("rep; vmmcall\n\r"); }

/* Taken from /arch/x86/include/asm/svm.h */
struct ghcb_save_area {
	u8 reserved_1[203];
	u8 cpl;
	u8 reserved_2[116];
	u64 xss;
	u8 reserved_3[24];
	u64 dr7;
	u8 reserved_4[16];
	u64 rip;
	u8 reserved_5[88];
	u64 rsp;
	u8 reserved_6[24];
	u64 rax;
	u8 reserved_7[264];
	u64 rcx;
	u64 rdx;
	u64 rbx;
	u8 reserved_8[8];
	u64 rbp;
	u64 rsi;
	u64 rdi;
	u64 r8;
	u64 r9;
	u64 r10;
	u64 r11;
	u64 r12;
	u64 r13;
	u64 r14;
	u64 r15;
	u8 reserved_9[16];
	u64 sw_exit_code;
	u64 sw_exit_info_1;
	u64 sw_exit_info_2;
	u64 sw_scratch;
	u8 reserved_10[56];
	u64 xcr0;
	u8 valid_bitmap[16];
	u64 x87_state_gpa;
}__attribute__((__packed__));

#define GHCB_SHARED_BUF_SIZE	2032

struct ghcb {
	struct ghcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct ghcb_save_area)];
	u8 shared_buffer[GHCB_SHARED_BUF_SIZE];
	u8 reserved_1[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
}__attribute__((__packed__));

struct ghcb_state {
	struct ghcb *ghcb;
};

/* GHCB Accessor functions */
static unsigned long UL(int a) {
    unsigned long ret = a;
    return ret;
}

#define BITS_PER_LONG 64
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

extern struct ghcb* ghcb;

// static __always_inline 
static inline void __set_bit(unsigned int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
#if 0
	/* Debugging the set_bit */
	printf("Setting offset --> %p\n", (void*) ((unsigned long) p - (unsigned long) ghcb));
#endif
	*p  |= mask;
}

static inline bool test_bit(int nr, const void *addr)
{
	const u32 *p = (const u32 *)addr;
	return ((1UL << (nr & 31)) & (p[nr >> 5])) != 0;
}

#define GHCB_BITMAP_IDX(field)							\
	(offsetof(struct ghcb_save_area, field) / sizeof(u64))

#define DEFINE_GHCB_ACCESSORS(field)						\
	static inline bool ghcb_##field##_is_valid(const struct ghcb *ghcb)	\
	{									\
		return test_bit(GHCB_BITMAP_IDX(field),				\
				(unsigned long *)&ghcb->save.valid_bitmap);	\
	}									\
										\
	static inline u64 ghcb_get_##field(struct ghcb *ghcb)			\
	{									\
		return ghcb->save.field;					\
	}									\
										\
	static inline u64 ghcb_get_##field##_if_valid(struct ghcb *ghcb)	\
	{									\
		return ghcb_##field##_is_valid(ghcb) ? ghcb->save.field : 0;	\
	}									\
										\
	static inline void ghcb_set_##field(struct ghcb *ghcb, u64 value)	\
	{									\
		__set_bit(GHCB_BITMAP_IDX(field),				\
			  (unsigned long *)&ghcb->save.valid_bitmap);		\
		ghcb->save.field = value;					\
	}

DEFINE_GHCB_ACCESSORS(cpl)
DEFINE_GHCB_ACCESSORS(rip)
DEFINE_GHCB_ACCESSORS(rsp)
DEFINE_GHCB_ACCESSORS(rax)
DEFINE_GHCB_ACCESSORS(rcx)
DEFINE_GHCB_ACCESSORS(rdx)
DEFINE_GHCB_ACCESSORS(rbx)
DEFINE_GHCB_ACCESSORS(rbp)
DEFINE_GHCB_ACCESSORS(rsi)
DEFINE_GHCB_ACCESSORS(rdi)
DEFINE_GHCB_ACCESSORS(r8)
DEFINE_GHCB_ACCESSORS(r9)
DEFINE_GHCB_ACCESSORS(r10)
DEFINE_GHCB_ACCESSORS(r11)
DEFINE_GHCB_ACCESSORS(r12)
DEFINE_GHCB_ACCESSORS(r13)
DEFINE_GHCB_ACCESSORS(r14)
DEFINE_GHCB_ACCESSORS(r15)
DEFINE_GHCB_ACCESSORS(sw_exit_code)
DEFINE_GHCB_ACCESSORS(sw_exit_info_1)
DEFINE_GHCB_ACCESSORS(sw_exit_info_2)
DEFINE_GHCB_ACCESSORS(sw_scratch)
DEFINE_GHCB_ACCESSORS(xcr0)


// Common.h
#define OCALL_printf 0x1234


extern int devfd;
void hello_world_enclave(void);

/* init.c */
bool open_device_driver(void);
bool create_enclave(void);
bool establish_ghcb(void);
void start_enclave(void);
void exit_enclave(void);
int setup_enclave(void);
void terminate_enclave(void);
bool init_enclave(void);

/* debug.c */
void 			dump_vmcb(void);
long 			get_current_cpu(void);
unsigned long 	custom_read_rsp(void);
bool 			resume_with_new_vmsa(void);
void 			assert_correct_cpu(void);





bool syscall_init(void);
void syscall_fini(void);
void syscall_handler(void);
void ocall_getpid(void);
int ocall_open(char* name, int mode);
void* ocall_mmap(void* tmp, unsigned long size, unsigned long prot,
    unsigned long attrs, int fd, int zero);
void ocall_read(int fd, void* buf, size_t count);
void ocall_printf(char* buf);
long ocall_common(long sysno, long a1, long a2, long a3, long a4, long a5, long a6);

/* benchmarks.c */
void open_enclave_benchmark(void);
void getpid_enclave_benchmark(void);
void mmap_enclave_benchmark(void);
void read_enclave_benchmark(void);

void open_native_benchmark(void);
void getpid_native_benchmark(void);
void mmap_native_benchmark(void);
void read_native_benchmark(void);

// IOCTL.h below 
struct vmod_ioctl_test_request {
    unsigned long addr;
    unsigned long stackaddr;
};

struct vmod_ioctl_establish_ghcb_request {
    unsigned long uvaddr;
    unsigned long paddr;
    unsigned long sev_status;
};

/* IOCTL-related definitions and structs. */
#define TEST                    _IOW('a', 'a', struct vmod_ioctl_test_request)
#define ESTABLISHGHCB           _IOW('a', 'b', struct vmod_ioctl_establish_ghcb_request)
#endif 

/* syscall_[enclave/untrusted].c */
typedef struct {
	long ret;
    long syscall_no;
    long arg1;
    long arg2;
    long arg3;
    long arg4;
    long arg5;
	long arg6;
} syscall_msg_buffer;
extern syscall_msg_buffer* sc_buf;


/* for open ocall */
typedef struct {
    char name[128];
    int name_size;
    int mode;
}ocall_open_buffer;
extern ocall_open_buffer* oc_buf;

/* fancy print statements */
#define enclave_printf(args...) \
    printf("enclave: " args)

#define untrusted_printf(args...) \
    printf("app: " args)

extern struct ghcb* ghcb;

bool syscall_init(void);
void syscall_fini(void);

#endif