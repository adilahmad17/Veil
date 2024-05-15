#include <linux/file.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/mm.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/kthread.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/mutex.h>
#include <linux/gfp.h>
#include <linux/pid.h>

#include <linux/audit.h>

#include <net/sock.h>
#include <net/netlink.h>
#include <linux/skbuff.h>
#ifdef CONFIG_SECURITY
#include <linux/security.h>
#endif
#include <linux/freezer.h>
#include <linux/pid_namespace.h>
#include <net/netns/generic.h>

#include <asm/sev.h>
#include <asm/smp.h>
#include <asm/svm.h>
#include <linux/percpu-defs.h>
#include <asm/apic.h>
#include <asm/stacktrace.h>

#include "audit.h"
#include "audit_veil.h"

#include "../../../driver/common.h"

DEFINE_PER_CPU(void*, log_transit_buffer);
EXPORT_SYMBOL(log_transit_buffer);
bool logging_service = false;
EXPORT_SYMBOL(logging_service);

bool is_logging_service_enabled(void) {return logging_service;}

// call the security monitor for log protection
void invoke_logging_service_protection(unsigned long logmsg, unsigned long logsize) {
    char* this_transit_buffer = this_cpu_read(log_transit_buffer);
	struct svsm_caa *this_caa = this_cpu_read(svsm_caa);
    if (this_transit_buffer) {
        // truncating since our log buffer is 1KB; i don't think i've ever seen
        // a larger message, but just for sanity
        if (logsize > 1024) {
            printk("Warning: truncating the log message to 1KB!\n");
            memcpy(this_transit_buffer, (void*) logmsg, 1024);
        } else {
            memcpy(this_transit_buffer, (void*) logmsg, logsize);
        }
    } else {
        // should not really come here as well!
        printk("Error: the buffer is not allocated.\n");
        return;
    }

	// protocol 0, call identifier 12: SVSM_LOGGING_SERVICE_PROT
	__svsm_msr_protocol(this_caa, 12, 
        virt_to_phys(this_transit_buffer), logsize, 0, 0);
}

// for each vcpu, we register a secure buffer inside the monitor's memory
// then, signal kernel audit functions that logs must now be protected
void kernel_logging_service_init(void) {
    // allocate a per-cpu kernel buffer
    logging_service = true;
}
EXPORT_SYMBOL(kernel_logging_service_init);

void kernel_logging_service_fini(void){
    // signal kernel audit functions to revert back to old mechansims
    logging_service = false;

}
EXPORT_SYMBOL(kernel_logging_service_fini);