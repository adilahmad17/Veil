#include <linux/sched/debug.h>	/* For show_regs() */
#include <linux/percpu-defs.h>
#include <linux/cc_platform.h>
#include <linux/printk.h>
#include <linux/mm_types.h>
#include <linux/set_memory.h>
#include <linux/memblock.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/efi.h>
#include <linux/platform_device.h>
#include <linux/io.h>

#include <asm/cpu_entry_area.h>
#include <asm/stacktrace.h>
#include <asm/sev.h>
#include <asm/insn-eval.h>
#include <asm/fpu/xcr.h>
#include <asm/processor.h>
#include <asm/realmode.h>
#include <asm/setup.h>
#include <asm/traps.h>
#include <asm/svm.h>
#include <asm/smp.h>
#include <asm/cpu.h>
#include <asm/apic.h>
#include <asm/cpuid.h>
#include <asm/setup.h>

#include "common.h"

unsigned long custom_read_cr3(void)
{
	unsigned long val;
	asm volatile("mov %%cr3,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

unsigned long custom_read_cr4(void)
{
	unsigned long val;
	asm volatile("mov %%cr4,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

unsigned long custom_read_cr0(void)
{
	unsigned long val;
	asm volatile("mov %%cr0,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

unsigned long custom_read_cr2(void)
{
	unsigned long val;
	asm volatile("mov %%cr2,%0\n\t" : "=r" (val), "=m" (__force_order));
	return val;
}

unsigned long custom_read_rbp(void)
{
	unsigned long val;
	asm volatile("mov %%rbp,%0\n\t" : "=m" (val));
	return val;
}

unsigned long custom_read_rsp(void)
{
	unsigned long val;
	asm volatile("mov %%rsp,%0\n\t" : "=m" (val));
	return val;
}

void custom_store_gdt(struct desc_ptr *dtr)
{
	asm volatile("sgdt %0":"=m" (*dtr));
}

void custom_store_idt(struct desc_ptr *dtr)
{
	asm volatile("sidt %0":"=m" (*dtr));
}

void custom_store_ldt(struct desc_ptr *dtr)
{
	asm volatile("sldt %0":"=m" (*dtr));
}

struct vmcb_seg custom_store_tr(void)
{
    struct vmcb_seg tss_seg;
	unsigned long tr;
    struct desc_ptr dp;
    struct desc_struct *d;
	tss_desc tss;

    /* Retrieve the selector */
	asm volatile("str %0":"=r" (tr));
    tss_seg.selector = tr; 

    /* Retrieve the GDT first */
    custom_store_gdt(&dp);
    d = (struct desc_struct*) dp.address;

    /* Copy the TSS entry */
	memcpy(&tss, &d[GDT_ENTRY_TSS], sizeof(tss_desc));

    tss_seg.base    = (unsigned long) 
                        ( ((unsigned long) (tss.base3) << 32) | 
                          ((unsigned long) (tss.base2) << 24) | 
                          ((unsigned long) (tss.base1) << 16) | 
                          (unsigned long) (tss.base0));
    
    /* Retrieved from the KVM dump */
    tss_seg.attrib  = 0x89;

    /* Set the limit */
    tss_seg.limit   = tss.limit0 + tss.limit1;

    return tss_seg;
}

