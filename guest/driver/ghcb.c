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

#include "ioctl-defines.h"
#include "common.h"

#define PTE_ENC_BIT					BIT(51)
extern unsigned long __force_order;

inline u64 rd_sev_status_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV));

	return ((high << 32) | low);
}

static inline u64 sev_es_rd_ghcb_msr(void)
{
	unsigned long low, high;

	asm volatile("rdmsr" : "=a" (low), "=d" (high) :
			"c" (MSR_AMD64_SEV_ES_GHCB));

	return ((high << 32) | low);
}

static inline void sev_es_wr_ghcb_msr(u64 val)
{
	u32 low, high;

	low  = val & 0xffffffffUL;
	high = val >> 32;

	asm volatile("wrmsr" : : "c" (MSR_AMD64_SEV_ES_GHCB),
			"a"(low), "d" (high) : "memory");
}

static inline void custom_flush_tlb_single(unsigned long addr)
{
	asm volatile("invlpg (%0)" ::"r" (addr) : "memory");
}

static inline void custom_write_cr3(unsigned long val)
{
	asm volatile("mov %0,%%cr3": : "r" (val), "m" (__force_order));
}

static inline void custom_flush_tlb(void)
{
	custom_write_cr3(custom_read_cr3());
}

#if 0
static void print_ul_to_binary(unsigned long k)
{
    char c[65];
    unsigned long val;

    c[0] = '\0';
    for (val = 1UL << (sizeof(unsigned long)*8-1); val > 0; val >>= 1)
    {   
        strcat(c, ((k & val) == val) ? "1" : "0");
    }

    veil_driver_print("%lx = (binary) %s\n", k, c);
}
#endif

/* This function gets an unencrypted chunk of memory and sends it
 * to the user process to use as a GHCB. */
int establish_ghcb(struct ioctl_establish_ghcb_request *req) {
    struct ghcb *ghcb;
    struct ghcb_state state;
    struct vm_area_struct* cur_vma;
    unsigned long ghcb_paddr;
    unsigned long len;
    int ret;
    unsigned long flags;
    unsigned long tmp;
    int x;

    pte_t* ghcb_user_pte;
    pte_t* ghcb_kern_pte;
    int l, i;

    local_irq_save(flags);
    
    /* Get the enclave GHCB */
    ghcb = __enclave_sev_get_ghcb(&state);

    printk("GHCB address = %px\n", (void*) ghcb);

    /* Invalidate the GHCB before use */
    vc_ghcb_invalidate(ghcb);

#if 0
    /* Debugging to check offsets */
    veil_driver_print("GHCB statistics: \n");
    veil_driver_print("Size = %ld\n", sizeof(struct ghcb));
    veil_driver_print("Offsets: exit_code = %ld, info1 = %ld, info2 = %ld\n",
            GHCB_BITMAP_IDX(sw_exit_code),
            GHCB_BITMAP_IDX(sw_exit_info_1),
            GHCB_BITMAP_IDX(sw_exit_info_2));
#endif
    unsigned long a = req->uvaddr;
    printk("Vikram: size of req->uvadd: %lx\n", a);
    /* Find the VMA corresponding to user address */
    if ((cur_vma = find_vma(get_current()->mm, req->uvaddr)) == NULL) {
        veil_driver_print("Error: could not find VMA for uaddress (%px)\n",
            (void*) req->uvaddr);
        return -1;
    }

#if 0
    veil_driver_print("Current process:\n");
    veil_driver_print("Name = %s, Provided Address = %px\n",
        get_current()->comm, (void*) req->uvaddr);
#endif

    /* Find length of VMA */
    len = cur_vma->vm_end - cur_vma->vm_start;
    printk("Size of len: %lx\n", len);
    x = sizeof(struct ghcb);
    printk("Size of ghcb: %x\n", x);

    if (len != sizeof(struct ghcb)) {
        veil_driver_print("Error: Provided VMA should atleast be the size of GHCB.\n");
        return -1;
    }
    veil_driver_print("VMA Start = %px, End = %px Length = %ld\n", 
                (void*) cur_vma->vm_start, (void*) cur_vma->vm_end, len);

    /* Find physical address of ghcb */
    ghcb_paddr = __pa(ghcb);
    if (ghcb_paddr == 0) {
        veil_driver_print("Error: could not find PA for GHCB\n");
        return -1;
    }
    veil_driver_print("GHCB PA = %px\n", (void*) ghcb_paddr);

    /* Remap that GHCB to be available to the process
     *
     * Note: PAGE_SHARED allows for both read/write permissions.
     */
    ret = remap_pfn_range(cur_vma, cur_vma->vm_start,
            PHYS_PFN(ghcb_paddr), len, PAGE_SHARED);
    if (ret < 0) {
        veil_driver_print("Error: cannot remap (code = %d)\n", ret);
        return -1;
    }
    veil_driver_print("Success: remap completed successfully.\n");

    custom_flush_tlb();

    /* Reserve the pages */
    for(i = 0; i < len/PAGE_SIZE; i += PAGE_SIZE)
        SetPageReserved(virt_to_page(((unsigned long)ghcb) + i));

    /* Lookup entry and set 'c' bit to 0 in user PTE */
    ghcb_user_pte = lookup_address_in_mm(get_current()->mm,
                cur_vma->vm_start, &l);
    if (!ghcb_user_pte) {
        veil_driver_print("Error: could not find the user PTE.\n");
        return -1;
    }
    tmp = ~(tmp & 0);
    tmp ^= PTE_ENC_BIT;
    ghcb_user_pte->pte &= tmp;
    veil_driver_print("Physical address in PTE = %px\n",
        (void*) pte_val(*ghcb_user_pte));

    /* Sanity check */
    if (pte_val(*ghcb_user_pte) & PTE_ENC_BIT) {
		veil_driver_print("Error: GHCB page should not be encrypted.\n");
        return -1;
	}

#if 0
    /* Debugging */
    print_ul_to_binary((unsigned long) pte_val(*ghcb_user_pte));
    ghcb_kern_pte = lookup_address((unsigned long) ghcb, &l);
    print_ul_to_binary((unsigned long) pte_val(*ghcb_kern_pte));
#endif

    custom_flush_tlb();

    /* Let the process know the physical address */
    req->paddr = ghcb_paddr;

    /* Set the important bits and physical address */
    ghcb_set_rax(ghcb, (rd_sev_status_msr() >> 2));
    sev_es_wr_ghcb_msr(__pa(ghcb)); 
    
    /* Put the GHCB and restore flags */
    __enclave_sev_put_ghcb(&state);

    local_irq_restore(flags);

    veil_driver_print("Returning to process.\n");

    return 0;
}

/* This function unmaps the GHCB from the enclave's address space. */
void remove_ghcb(void) {
    struct ghcb *ghcb;
    struct ghcb_state state;
    unsigned long ghcb_paddr;
    unsigned long flags;

    int i;
    int len = sizeof(struct ghcb);

    local_irq_save(flags);

    /* Get the enclave GHCB */
    ghcb = __enclave_sev_get_ghcb(&state);

    /* Invalidate the GHCB before use */
    vc_ghcb_invalidate(ghcb);

    /* Find physical address of ghcb */
    ghcb_paddr = __pa(ghcb);
    if (ghcb_paddr == 0) {
        veil_driver_print("Error: could not find PA for GHCB\n");
        return;
    }
    veil_driver_print("GHCB PA = %px\n", (void*) ghcb_paddr);

    /* Unreserve the pages */
    for(i = 0; i < len/PAGE_SIZE; i += PAGE_SIZE)
        ClearPageReserved(virt_to_page(((unsigned long)ghcb) + i));
    
    custom_flush_tlb();

    /* Put the GHCB and restore flags */
    __enclave_sev_put_ghcb(&state);
    local_irq_restore(flags);
}