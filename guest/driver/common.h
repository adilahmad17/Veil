#ifndef __COMMON_H__
#define __COMMON_H__

#include <asm/sev.h>
#include <asm/smp.h>
#include <asm/svm.h>
#include <linux/percpu-defs.h>

// fancy print statement
#define veil_driver_print(args...) printk("veil-driver: " args)

// this is required for calling svsm
extern struct svsm_caa *svsm_caa;

// SEV-related definitions taken from the kernel source
#define MSR_AMD64_SEV_ES_GHCB		    0xc0010130
#define	VMGEXIT()			{ asm volatile("rep; vmmcall\n\r"); }
#define GHCB_NAE_RUN_VMPL 0x80000018
#define GHCB_SHARED_BUF_SIZE	2032
struct ghcb_state {
	struct ghcb *ghcb;
};

// defined: log.c
char*   retrieve_logs(unsigned long size, unsigned long offset);
bool    logging_service_init(void);
void    logging_service_fini(void);

// defined: ioctl.c
bool ioctl_init(void);
void ioctl_fini(void);

// defined: helpers.c
unsigned long   custom_read_cr3(void);
unsigned long   custom_read_cr4(void);
unsigned long   custom_read_cr0(void);
unsigned long   custom_read_cr2(void);
unsigned long   custom_read_rbp(void);
unsigned long   custom_read_rsp(void);
void            custom_store_gdt(struct desc_ptr *dtr);
void            custom_store_idt(struct desc_ptr *dtr);
void            custom_store_ldt(struct desc_ptr *dtr);
struct vmcb_seg custom_store_tr(void);

// defined: ghcb.c
int establish_ghcb(struct ioctl_establish_ghcb_request *req);
void remove_ghcb(void);

// defined: enclave.c
int create_enclave(struct ioctl_enclave_request* req);

// external definitions from the kernel source below
// defined: guest/linux/kernel/audit_veil.c
extern void     kernel_logging_service_init(void);
extern void     kernel_logging_service_fini(void);
extern void*    log_transit_buffer;    // per-cpu transit buffer
extern bool     logging_service;

// defined: various locations within the kernel (e.g., use grep or elixir)
extern void*            snp_alloc_vmsa_page(void);
extern unsigned long    __force_order;
struct ghcb*            __enclave_sev_get_ghcb(struct ghcb_state *state);
void                    __enclave_sev_put_ghcb(struct ghcb_state *state);
inline u64              rd_sev_status_msr(void);

#endif