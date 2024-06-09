/* SPDX-License-Identifier: MIT */
use crate::cpu::*;
use crate::mem::*;
use crate::*;

use x86_64::addr::*;
use core::ptr::copy_nonoverlapping;

const SVSM_SUCCESS: u64 = 0;

/* This function starts the enclave test program at VMPL2 with a given 
 * Virtual Machine Save Area (VMSA). In principle, this should be handled
 * entirely within SVSM, but for simplicity the VMSA is provided by the
 * kernel for now.
 */
pub unsafe fn create_enclave_test(vmsa: *mut Vmsa) {
    prints!("Creating enclave test\n");

    let apic_id: u32 = LOWER_32BITS!((*vmsa).r9()) as u32;
    let cpu_id: usize = match smp_get_cpu_id(apic_id) {
        Some(c) => c,
        None => return,
    };
    prints!("APIC ID: {apic_id}\n");
    
    let create_vmsa_gpa: PhysAddr = PhysAddr::new((*vmsa).r8());
    let create_vmsa_va: VirtAddr = match pgtable_map_pages_private(create_vmsa_gpa, VMSA_MAP_SIZE) {
        Ok(v) => v,
        Err(_e) => return,
    };
    let create_vmsa: *mut Vmsa = create_vmsa_va.as_mut_ptr();
    pgtable_print_pte_va(create_vmsa_va);

    let ret: u32 = rmpadjust(create_vmsa_va.as_u64(), RMP_4K, VMSA_PAGE | VMPL::Vmpl2 as u64);
        if ret != 0 {
        vc_terminate_svsm_general();
    }
    (*vmsa).set_rax(SVSM_SUCCESS);

    let vmpl = (*create_vmsa).vmpl();
    prints!("Enclave VMSA VMPL: {vmpl}\n");
    let stack_base = (*create_vmsa).rsp();
    prints!("Enclave stack base is at: {:#0x}\n", stack_base);
    let entry_function = (*create_vmsa).rip();
    prints!("Enclave entry function is at: {:#0x}\n", entry_function);

    {
        PERCPU.set_vmsa_for(create_vmsa_gpa, VMPL::Vmpl2, cpu_id);
        prints!("Set new VMSA for VMPL2 - enclave\n");
        enclave_vc_ap_create(create_vmsa_va, apic_id);
        pgtable_unmap_pages(create_vmsa_va, PAGE_SIZE);
    }    
}

unsafe fn handle_enclave_secure_copy(vmsa: *mut Vmsa) {
    prints!("Hello from the secure copy request in SVSM!\n");
    let srcaddr: u64 = (*vmsa).rcx();
    let dstaddr: u64 = (*vmsa).rdx();
    let _num_pages: u64 = (*vmsa).r8();
    let _apic_id: u32 = LOWER_32BITS!((*vmsa).r9()) as u32;

    //Map both pages into SVSM's memory
    let srcaddr_page_pa: PhysAddr = PhysAddr::new(srcaddr);
    let srcaddr_page_va: VirtAddr = match pgtable_map_pages_private(srcaddr_page_pa, 4096) {
        Ok(v) => v,
        Err(_e) => return,
    };

    let dstaddr_page_pa: PhysAddr = PhysAddr::new(dstaddr);
    let dstaddr_page_va: VirtAddr = match pgtable_map_pages_private(dstaddr_page_pa, 4096) {
        Ok(v) => v,
        Err(_e) => return,
    };

    //Copy page from one space to another space
    let size: u64 = 4096;
    let dstaddr: *mut u8 = dstaddr_page_va.as_mut_ptr();
    let srcaddr: *const u8 = srcaddr_page_va.as_ptr();
    copy_nonoverlapping(srcaddr, dstaddr, size as usize);

    prints!("Done with secure copy request in SVSM!\n");
    (*vmsa).set_rax(SVSM_SUCCESS);
}