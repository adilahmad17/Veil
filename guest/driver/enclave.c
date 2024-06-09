#include <linux/blkdev.h>
#include <linux/completion.h>
#include <linux/dcache.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kref.h>
#include <linux/kthread.h>
#include <linux/limits.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/freezer.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>
#include <linux/usb/composite.h>
#include <linux/cdev.h>
#include <linux/nospec.h>
#include <linux/kallsyms.h>

#include <asm/fpu/xcr.h>
#include <asm/apic.h>
#include <asm/stacktrace.h>

#include "ioctl-defines.h"
#include "common.h"

struct sev_es_save_area* 
create_enclave_vmsa(unsigned long enclave_address, unsigned long stack_base){
    struct sev_es_save_area *vmsa;
    struct task_struct* cur_ts;
	struct mm_struct* cur_mm;

	struct desc_ptr gdtr, idtr, ldtr;
	unsigned long kernel_gs;
	unsigned long fs_base;
	struct vmcb_seg tr;
	unsigned int sysenter_cs, sysenter_esp, sysenter_eip;
	unsigned long efer = 0;
	unsigned long star = 0, lstar = 0, cstar = 0, sfmask = 0;
	struct pt_regs* cur_pt_regs;

    /* Create a new VMSA for this enclave */
	vmsa = (struct sev_es_save_area *) snp_alloc_vmsa_page();
    if (!vmsa) {
		veil_driver_print("Error: could not allocate memory for VMSA.\n");
		return NULL;
	}

    /* Get current process' task_struct and mm_struct */
	cur_ts = get_current();
	if (cur_ts == NULL) {
		veil_driver_print("Error: could not find current process' task_struct.\n");
		return NULL;
	}
	cur_mm = cur_ts->mm;
	if (cur_mm == NULL) {
		veil_driver_print("Error: could not find current process' mm_struct.\n");
		return NULL;
	}

    /* Write current control register state to the VMSA */
	vmsa->cr0 = custom_read_cr0();
	vmsa->cr2 = custom_read_cr2();

    /* TODO: In practice, this should be a secure copy of the page tables */
	vmsa->cr3 = __sme_pa(cur_mm->pgd);
    // vmsa->cr3 = __sme_pa(recurse_pgd());

	vmsa->cr4 = custom_read_cr4();
	vmsa->xcr0 = xgetbv(0);

	/* Get the current process saved registers */
	cur_pt_regs = task_pt_regs(cur_ts);

	/* Set the CS value based on the start_ip converted to a SIPI vector */
	vmsa->cs.base		= 0;
	vmsa->cs.limit		= 0xffffffff;
	vmsa->cs.attrib		= 0x2fb;

	// NOTE: This was obtained from a VMCS dump (in debug mode). In practice, this should
    // be corrected and set according to specification.
	vmsa->cs.selector   = cur_pt_regs->cs;
	
	vmsa->ss.base		= 0;
	vmsa->ss.limit		= 0xffffffff;
	vmsa->ss.attrib		= 0xcf3;

	// NOTE: currently fetched from the kernel
    vmsa->ss.selector	= cur_pt_regs->ss;

    /* Set the kernel GS, FS base. */
	rdmsrl(MSR_GS_BASE, kernel_gs);
	vmsa->kernel_gs_base 	 = kernel_gs;
    vmsa->gs.base = 0x7ffffffcaef0;
    vmsa->gs.limit = 0x0;
    vmsa->gs.attrib = 0x0;
    vmsa->gs.selector = 0x0;
	
    rdmsrl(MSR_FS_BASE, fs_base);
    vmsa->fs.base 	  		 = fs_base;

	/* Set the RIP to start from enclave entry function */
	vmsa->rip = enclave_address;
    veil_driver_print("rip: %px", (void*)enclave_address);

	/* Set the RSP to start from stack base in userspace */
	vmsa->rsp = stack_base;
    veil_driver_print("stack base: %px", (void*)stack_base);

	/* Retrieve current GDTR/IDTR/LDTR */
	custom_store_gdt(&gdtr);
	custom_store_idt(&idtr);
	custom_store_ldt(&ldtr);
	tr = custom_store_tr();

	/* Set the GDTR based on current values */
	vmsa->gdtr.base		= gdtr.address;
	vmsa->gdtr.limit	= gdtr.size;

	/* Set the IDTR based on current values */
	vmsa->idtr.base		= idtr.address;
	vmsa->idtr.limit	= idtr.size;

	/* Set the TR based on current values */
	vmsa->tr 			= tr;

	/* Set the EFER value (according to dumps from KVM) */
	rdmsrl(MSR_EFER, efer);
	vmsa->efer			= efer;
	
	/* Left the remaining values to what SEV-SNP originally sets */
    vmsa->dr6			= 0xffff0ff0;
	vmsa->dr7			= 0x400;

	/* Obtained RFLAGS value from process saved state. */
	//vmsa->rflags		= 0x217;
    vmsa->rflags		= 0x206;
	
	/* Second one is based on KVM dump */
	vmsa->g_pat		= 0x0407050600070106ULL;

	/* NOTE: Values obtained from the KVM dump of the VMCB/VMSA */
	//vmsa->xcr0		= 7;
	vmsa->xcr0			= 7;
	//vmsa->mxcsr		= 0x1f80;
	vmsa->mxcsr			= 0x1f80;
	//vmsa->x87_ftw		= 0x0;
	vmsa->x87_ftw		= 0x0;
	//vmsa->x87_fcw		= 0x37f;
	vmsa->x87_fcw		= 0x37f;

	/* Set the SYSENTER state */
	rdmsrl(MSR_IA32_SYSENTER_CS, sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_EIP, sysenter_eip);
	rdmsrl(MSR_IA32_SYSENTER_ESP, sysenter_esp);
	vmsa->sysenter_cs = sysenter_cs;
	vmsa->sysenter_eip = sysenter_eip;
	vmsa->sysenter_esp = sysenter_esp;

	/* Set the star, lstar, cstar */
	rdmsrl(MSR_STAR, star);
	rdmsrl(MSR_LSTAR, lstar);
	rdmsrl(MSR_CSTAR, cstar);
	rdmsrl(MSR_SYSCALL_MASK, sfmask);
	vmsa->star = star;
	vmsa->lstar = lstar;
	vmsa->cstar = cstar;
	vmsa->sfmask = sfmask;

	/*
	 * Set the SNP-specific fields for this VMSA:
	 *   VMPL level
	 *   SEV_FEATURES (matches the SEV STATUS MSR right shifted 2 bits)
	 */
    // Enclave is at VMPL2
	vmsa->vmpl		    = 2; 
	vmsa->cpl			= 3;
	vmsa->sev_features	= (rd_sev_status_msr() >> 2);

    return vmsa;
}

int 
create_enclave(struct ioctl_enclave_request* req) {
    
    u32 apic_id;
    unsigned long enclave_address = req->addr;
    unsigned long stack_base = req->stackaddr;
    
    /* Debugging */
    veil_driver_print("enclave address = %px\n", (void*) enclave_address);

    /* Call the secmon to create a VMSA. */
	struct svsm_caa *this_caa;
    this_caa = this_cpu_read(svsm_caa);

    apic_id = read_apic_id();

    struct sev_es_save_area* vmsa;
    vmsa = create_enclave_vmsa(enclave_address, stack_base);

	/* Protocol 0, Call ID 14 */
	/* Creating AP with new VMSA for VMPL2 */	
    veil_driver_print("Before running __svsm_msr_protocol\n");
    veil_driver_print("VMSA (VA = %x, PA = %x)\n", vmsa, __pa(vmsa));


	__svsm_msr_protocol(this_caa, 14, 0, 0, __pa(vmsa), apic_id);

    /* Debugging */
    veil_driver_print("Enclave VMSA created.\n");

    return 0;
}
