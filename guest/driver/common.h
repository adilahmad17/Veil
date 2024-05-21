#ifndef __COMMON_H__
#define __COMMON_H__

#include <asm/sev.h>
#include <asm/smp.h>
#include <asm/svm.h>
#include <linux/percpu-defs.h>

// this is required for calling svsm
extern struct svsm_caa *svsm_caa;

// fancy print statement
#define veil_driver_print(args...) printk("veil-driver: " args)

// defined: log.c
char* retrieve_logs(unsigned long size, unsigned long offset);
bool logging_service_init(void);
void logging_service_fini(void);

// defined: ioctl.c
bool ioctl_init(void);
void ioctl_fini(void);

// external definitions from the kernel source below
// defined: guest/linux/kernel/audit_veil.c
extern void kernel_logging_service_init(void);
extern void kernel_logging_service_fini(void);
extern void* log_transit_buffer;    // per-cpu transit buffer
extern bool  logging_service;

#endif