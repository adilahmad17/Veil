/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Helpers/definitions related to MSR access.
 */

#ifndef BOOT_MSR_H
#define BOOT_MSR_H

#include <asm/shared/msr.h>

/*
 * The kernel proper already defines rdmsr()/wrmsr(), but they are not for the
 * boot kernel since they rely tracepoint/exception handling infrastructure
 * that's not available here, hence these boot_{rd,wr}msr helpers which serve
 * the singular purpose of wrapping the RDMSR/WRMSR instructions to reduce the
 * need for inline assembly calls throughout the boot kernel code.
 */
static inline void boot_rdmsr(unsigned int msr, struct msr *m)
{
	asm volatile("rdmsr" : "=a" (m->l), "=d" (m->h) : "c" (msr));
}

static inline void boot_wrmsr(unsigned int msr, const struct msr *m)
{
	asm volatile("wrmsr" : : "c" (msr), "a"(m->l), "d" (m->h) : "memory");
}

#endif /* BOOT_MSR_H */
