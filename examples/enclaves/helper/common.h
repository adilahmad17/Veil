#ifndef __COMMON_H__
#define __COMMON_H__

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef MUSL
#define	VMGEXIT()			    { asm volatile("rep; vmmcall\n\r"); }
#else
#define	VMGEXIT()			    { __asm__ __volatile__ ("rep; vmmcall\n\r"); }
#endif
#define GHCB_NAE_RUN_VMPL       0x80000018
#define SVM_VMGEXIT_HELLO_WORLD 0x80000021

typedef uint8_t    u8;
typedef uint16_t   u16;
typedef uint32_t   u32;
typedef uint64_t   u64;

#define MSR_AMD64_SEV_ES_GHCB		    0xc0010130

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
};
// }__attribute__((__packed__));

#define GHCB_SHARED_BUF_SIZE	2032

struct ghcb {
	struct ghcb_save_area save;
	u8 reserved_save[2048 - sizeof(struct ghcb_save_area)];
	u8 shared_buffer[GHCB_SHARED_BUF_SIZE];
	u8 reserved_1[10];
	u16 protocol_version;	/* negotiated SEV-ES/GHCB protocol version */
	u32 ghcb_usage;
};
// }__attribute__((__packed__));

/* GHCB Accessor functions */
static unsigned long UL(int a) {
    unsigned long ret = a;
    return ret;
}

#define BITS_PER_LONG 64
#define BIT_MASK(nr)		(UL(1) << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

#ifndef MUSL
static __always_inline void
#else 
static inline void
#endif
__set_bit(unsigned int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);
	*p  |= mask;
}

static inline bool 
test_bit(int nr, const void *addr)
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

/* ================================================================== */

extern int devfd;
void hello_world_enclave(void);

/* init.c */
bool open_device_driver(void);
bool establish_ghcb(void);
bool create_enclave(void);
void start_enclave(void);
void exit_enclave(void);
void hello_world(void);
extern unsigned long enclave_entry;

/* debug.c */
int get_current_cpu(void);
void assert_correct_cpu(void);

#endif