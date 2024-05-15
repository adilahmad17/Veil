#include <linux/kthread.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kallsyms.h>
#include <linux/skbuff.h>
#include <linux/freezer.h>
#include <linux/mutex.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>
#include <linux/genhd.h>
#include <linux/blkdev.h>
#include <linux/hrtimer.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/sched/types.h>
#include <linux/pci.h>
#include <linux/kallsyms.h>
#include <asm/apic.h>
#include <asm/stacktrace.h>
#include "common.h"

// allocate percpu transit buffers
bool allocate_percpu_transit_buffer(void* info) {
    // kmalloc is required for virt_to_phys() to work
    void *this_log_transit_buffer = (void*) kmalloc(1024, GFP_KERNEL);
    if (this_log_transit_buffer == NULL) return false;
    this_cpu_write(log_transit_buffer, this_log_transit_buffer);
    return true;
}

// free percpu transit buffers
void free_percpu_transit_buffer(void* info) {
    void   *this_log_transit_buffer = this_cpu_read(log_transit_buffer);
    if (this_log_transit_buffer) kfree(this_log_transit_buffer);
}

// send a spurious test message to the security monitor
void test_logging_service(void) {
    char* this_transit_buffer = this_cpu_read(log_transit_buffer);
	struct svsm_caa *this_caa = this_cpu_read(svsm_caa);
    if (this_transit_buffer) {
        snprintf(this_transit_buffer, 6, "Hello!");
    } else {
        printk("Error: the buffer is not allocated.\n");
        return;
    }

	// protocol 0, call identifier 12: SVSM_LOGGING_SERVICE_PROT
	__svsm_msr_protocol(this_caa, 12, 
        virt_to_phys(this_transit_buffer), 128, 0, 0);
}

void monitor_percpu_logging_service(void* nonce) {
	// protocol 0, call identifier 11: SVSM_LOGGING_SERVICE_INIT
	struct svsm_caa *this_caa       = this_cpu_read(svsm_caa);
	void   *this_log_transit_buffer = this_cpu_read(log_transit_buffer);
    __svsm_msr_protocol(this_caa, 11, 
        virt_to_phys(this_log_transit_buffer), 0, 0, 0);
}

// Initialize the log buffer on each vcpu within monitor
// Signal the kernel to start sending logs to monitor
bool logging_service_init(void) {
    // allocate a transit log buffer on each cpu
    // TODO: make this multi-cpu capable
    if (!allocate_percpu_transit_buffer(NULL)) {
        printk("Error: could not allocate the transit buffer.\n");
        return false;
    }
    monitor_percpu_logging_service(NULL);
    
    // send a test message
    // signal the internal kernel audit subsystem
    test_logging_service();

    kernel_logging_service_init();
    return true;
}

// Signal the kernel to stop sending logs to monitor
// Discard the log buffer on each vcpu within monitor
void logging_service_fini(void) {
    kernel_logging_service_fini();
    free_percpu_transit_buffer(NULL);
    veil_driver_print("Disabled logging service on all CPUs.\n");
}