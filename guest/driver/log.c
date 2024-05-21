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

bool logging_service_initialized = false;

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
    int i = 0;
    int test_iterations = 1;
    char* this_transit_buffer = this_cpu_read(log_transit_buffer);
	struct svsm_caa *this_caa = this_cpu_read(svsm_caa);

    printk("Testing the logging service .. \n");
    if (this_transit_buffer) {
        snprintf(this_transit_buffer, 6, "Hello!");
    } else {
        printk("Error: the buffer is not allocated.\n");
        return;
    }

	// protocol 0, call identifier 12: SVSM_LOGGING_SERVICE_PROT
    // arguments: <log_entry_location>, <log_entry_size>, 0, 0
    for (i = 0; i < test_iterations; i++) {
	    __svsm_msr_protocol(this_caa, 12, 
            virt_to_phys(this_transit_buffer), 128, 0, 0);
    }
}

// retrieve logs from the protected buffer
char* retrieve_logs(unsigned long size, unsigned long offset) {
    char* this_transit_buffer = this_cpu_read(log_transit_buffer);
	struct svsm_caa *this_caa = this_cpu_read(svsm_caa);
    int chunksize = 128;
    int retrieved = 0;

    // sanity check(s)
    if (!logging_service_initialized) {
        veil_driver_print("Error: logging service is not initialized.\n");
        return NULL;
    }

    char* kernel_buffer = vmalloc(size);
    if (!kernel_buffer) {
        veil_driver_print("Error: kernel buffer could not be allocated.\n");
        return NULL;
    }

	// protocol 0, call identifier 13: SVSM_LOGGING_SERVICE_DUMP
    while (retrieved < size) {
        // breakdown into smaller chunks (TODO: optimize later.)
	    __svsm_msr_protocol(this_caa, 13, 0, chunksize, offset+retrieved, 0);
        memcpy(kernel_buffer+retrieved, this_transit_buffer, chunksize);
        retrieved += chunksize;
    }

    return kernel_buffer;
}

void monitor_percpu_logging_service(void* nonce) {
	// protocol 0, call identifier 11: SVSM_LOGGING_SERVICE_INIT
    // arguments: <log_entry_location>, 0, 0, 0
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
    logging_service_initialized = true;

    // test retrieval
    retrieve_logs(512, 0);
    return true;
}

// Signal the kernel to stop sending logs to monitor
// Discard the log buffer on each vcpu within monitor
void logging_service_fini(void) {
    kernel_logging_service_fini();
    free_percpu_transit_buffer(NULL);
    logging_service_initialized = false;
    veil_driver_print("Disabled logging service on all CPUs.\n");
}