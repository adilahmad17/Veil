/* This file contains the IOCTL implementation for the veil-driver module */
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
#include <asm/pgalloc.h>

#include <linux/ioctl.h>

#include <linux/usb/ch9.h>
#include <linux/usb/gadget.h>
#include <linux/usb/composite.h>

#include <asm/fpu/xcr.h>

#include <linux/cdev.h>
#include <linux/nospec.h>
#include <linux/kallsyms.h>

#include <asm/apic.h>
#include <asm/stacktrace.h>

#include "common.h"
#include "ioctl-defines.h"

static dev_t dev = 0;
static struct class* vmod_class;
static struct cdev   vmod_cdev;

struct ioctl_dump_logs ioctl_dl;

/* ioctl handler */
static long vmod_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
    char* kbuf;
    veil_driver_print("ioctl: executing.\n");

    switch (cmd)
    {
        case DUMP_LOGS:
            veil_driver_print("ioctl: DUMP_LOGS\n");
            
            /* copy data from user */
            if (copy_from_user((void*) &ioctl_dl, (void*) arg, 
                    sizeof(struct ioctl_dump_logs))) {
                veil_driver_print("error: user didnt send correct DUMP_LOGS message.\n");
                return -1;
            }
            veil_driver_print("input: (%px, %ld, %ld)\n",
                (void*) ioctl_dl.address, ioctl_dl.size, ioctl_dl.offset);

            /* retrieve logs from monitor */
            kbuf = retrieve_logs(ioctl_dl.size, ioctl_dl.offset);

            /* copy logs to user memory */
            if (kbuf != NULL) {
                veil_driver_print("copying to user: (%px, %px, %ld)\n",
                (void*) ioctl_dl.address, (void*) kbuf, ioctl_dl.size);
                if (copy_to_user((void*) ioctl_dl.address, kbuf, ioctl_dl.size)) {
                    veil_driver_print("error: copy_to_user failed.\n");
                    return -1;
                }
            }
            else {
                veil_driver_print("error: log buffer is not valid.\n");
            }

            veil_driver_print("success: logs dumped.\n");
            break;
        
        default: 
            veil_driver_print("ioctl: wrong command sent\n");
    }

    return 0;
}

/* open function. */
static int vmod_open(struct inode* inode, struct file* file) {
    veil_driver_print("ioctl: open executed.\n");
    return 0;
}

/* release function. */
static int vmod_release(struct inode* inode, struct file* file) {
    veil_driver_print("ioctl: close executed.\n");
    return 0;
}

/* file operation struct. */
static struct file_operations fops = 
{
    .owner = THIS_MODULE,
    .open = vmod_open,
    .release = vmod_release,
    .unlocked_ioctl = vmod_ioctl,
};

/* initialize ioctl. */
bool ioctl_init(void) {
    if (alloc_chrdev_region(&dev, 0, 1, "veil-driver") < 0) {
        veil_driver_print("error: couldn't allocate chardev region.\n");
        return false;
    }
    veil_driver_print("success: allocated chardev region.\n");

    cdev_init(&vmod_cdev, &fops);
    if (cdev_add(&vmod_cdev, dev, 1) < 0) {
        veil_driver_print("error: couldn't add chardev.\n");
        goto cdevfailed;
    }
    veil_driver_print("success: added chardev.\n");

    if ((vmod_class = class_create(THIS_MODULE, "veil-driver-class")) == NULL) {
        veil_driver_print("error: couldn't create class.\n");
        goto cdevfailed;
    }
    veil_driver_print("success: created veil-driver-class.\n");

    if ((device_create(vmod_class, NULL, dev, NULL, "veil-driver")) == NULL) {
        veil_driver_print("error: couldn't create device.\n");
        goto classfailed;
    }
    veil_driver_print("success: veil-driver inserted.\n");
    return true;

classfailed:
    class_destroy(vmod_class);
cdevfailed:
    unregister_chrdev_region(dev, 1);
    return false;
}

/* teardown ioctl. */
void ioctl_fini(void) {
    if (vmod_class) {
        device_destroy(vmod_class, dev);
        class_destroy(vmod_class);
    }
    cdev_del(&vmod_cdev);
    unregister_chrdev_region(dev,1);
    veil_driver_print("Removed vmod device driver from host.\n");
}