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

#include "common.h"

bool logging_service=false;
module_param(logging_service, bool, S_IWUSR);

static int __init veil_driver_init(void) {
    veil_driver_print("[*] Hello World!\n");

    // Set up IOCTL for userspace access
    if (!ioctl_init()) return -1;

    // Setup the logging service
    if (logging_service) {
        if (!logging_service_init()) {return -1;}
    }
    
    return 0;
}

static void __exit veil_driver_fini(void) {
    veil_driver_print("[*] Goodbye World!\n");
    // Stop the logging service
    if (logging_service)
        logging_service_fini();

    // stop ioctl
    ioctl_fini();
}

module_init(veil_driver_init);
module_exit(veil_driver_fini);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Adil Ahmad");
MODULE_DESCRIPTION("Veil Kernel Device Driver");
MODULE_VERSION("0.01");