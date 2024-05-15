/* SPDX-License-Identifier: MIT */
use crate::cpu::*;
use crate::globals::*;
use crate::mem::*;
use crate::util::util::memcpy;
use crate::*;

use core::arch::asm;
use x86_64::addr::*;
use x86_64::structures::paging::PhysFrame;

static LOGFRAMES:   u64 = 10;
static mut frame_start: u64 = 0;
static mut frame_end:   u64 = 0;

/* This code currently allocates a secure buffer and copies provided
   logs into the buffer. If the buffer is fully-consumed, it circles back
   to the front of the buffer. */ 

pub unsafe fn init_log_buffer(vmsa: *mut Vmsa) {
    let transit_buffer_pa: u64      = (*vmsa).rcx();
    let apic_id: u32                = LOWER_32BITS!((*vmsa).r9()) as u32;
    let frame: PhysFrame;

    prints!("Initializing secure log buffer for APIC ({})\n", apic_id);

    // allocate a buffer with LOGFRAMES number of frames
    frame = match mem_allocate_frames(LOGFRAMES) {
        Some(f) => f,
        None => vc_terminate_svsm_enomem(),
    };

    // find and print the SVSM virtual address of the region
    frame_start = (pgtable_pa_to_va(frame.start_address())).as_u64();
    frame_end   = frame_start + (LOGFRAMES*4096);
    prints!("Successfully allocated log buffer ({:#x} - {:#x})\n", frame_start, frame_end);
}

pub unsafe fn prot_log_message(vmsa: *mut Vmsa) {
    let msg_pa: u64     = (*vmsa).rcx();
    let msg_size: u64   = (*vmsa).rdx();
    prints!("Protecting the generated log (msg_pa = {:#x}, msg_size = {:#x})\n", msg_pa, msg_size);

    // Find physical address of the log entry
    let msg_page_va: VirtAddr = match pgtable_map_pages_private(PhysAddr::new(msg_pa), 4096) {
        Ok(v) => v,
        Err(_e) => return,
    };
    let msg_ptr: *mut u64 = msg_page_va.as_mut_ptr();

    // copy logs from kernel memory into secure memory
    // copy semantics: (src, dst, size)
    memcpy(msg_ptr as *mut u64, frame_start as *mut u64, msg_size as usize);
}