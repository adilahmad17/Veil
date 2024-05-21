/* SPDX-License-Identifier: MIT */
use crate::cpu::*;
use crate::globals::*;
use crate::mem::*;
use crate::util::util::memcpy;
use crate::*;

use core::arch::asm;
use x86_64::addr::*;
use x86_64::structures::paging::PhysFrame;

/* This code currently allocates a secure buffer and copies provided
   logs into the buffer. If the buffer is fully-consumed, it circles 
   back to the front of the buffer. */ 

static logframes:               u64 = 10;
static framesize:               u64 = 4096;
static mut logframes_start:     u64 = 0;
static mut logframes_end:       u64 = 0;
static mut logframes_used:      u64 = 0;
static mut msgbuf:              u64 = 0;

// allocate a logframe buffer
pub unsafe fn initialize_logframes(vmsa: *mut Vmsa) {
    let msgbuf_phys: u64            = (*vmsa).rcx();
    let apic_id: u32                = LOWER_32BITS!((*vmsa).r9()) as u32;
    let frame: PhysFrame;

    // allocate N frames and store their location (TODO: make per-cpu)
    frame = match mem_allocate_frames(logframes) {
        Some(f) => f,
        None => vc_terminate_svsm_enomem(),
    };
    logframes_start = (pgtable_pa_to_va(frame.start_address())).as_u64();
    logframes_end   = logframes_start + (logframes*framesize);

    // save the address of the kernel's log message buffer and map it into the service's page table
    // this is mainly to avoid remapping an address each time. (TODO: make per-cpu, add check)
    let msgbuf_virt: VirtAddr = 
        match pgtable_map_pages_private(PhysAddr::new(msgbuf_phys), 4096) {
        Ok(v) => v,
        Err(_e) => return,
    };
    msgbuf = msgbuf_virt.as_u64();
    prints!("Allocated log buffer (range={:#x} - {:#x}) at APIC ({})\n", 
        logframes_start, logframes_end, apic_id);
}

// protect a provided log entry
pub unsafe fn protect_log_entry(vmsa: *mut Vmsa) {
    let msg_pa: u64     = (*vmsa).rcx();
    let mut msg_size: u64   = (*vmsa).rdx();
    
    // rust copy primitive requires alignment or else it panics
    // (TODO: find a better, less restrictive primitive for copy)
    msg_size = ALIGN!(msg_size, 64);

    // wrap around (this should be changed depending on use-case)
    if (logframes_used >= (logframes*framesize)) {
        logframes_used = 0;
    }

    // protect logs and move frame pointer
    let logframes_current: u64 = logframes_start + logframes_used;
    memcpy(msgbuf as *mut u64, logframes_current as *mut u64, msg_size as usize);
    logframes_used = logframes_used + msg_size;
    prints!("Protected log entry (kernelbuf={:#x}, logframe_addr={:#x}, size={:#x})\n", 
        msg_pa, logframes_current, msg_size);
}

// dump logs to kernel buffer
pub unsafe fn dump_logs(vmsa: *mut Vmsa) {
    let kernbuf_phys: u64       = (*vmsa).rcx();
    let requested_size          = (*vmsa).rdx();
    let requested_offset        = (*vmsa).r9();

    // sanity check(s)
    if ((requested_size+requested_offset) >= (logframes*framesize)) {
        prints!("Error: incorrect size/offset requested.\n");
        return;
    }

    // perform the copy
    let logframes_current: u64 = logframes_start + requested_offset;
    memcpy(logframes_current as *mut u64, msgbuf as *mut u64, requested_size as usize);
    prints!("Dumped logs (logframe_addr={:#x}, kernelbuf={:#x}, size={:#x})\n", 
        logframes_current, requested_size, requested_offset);
}