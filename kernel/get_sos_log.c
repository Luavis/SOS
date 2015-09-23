#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/delay.h>
#include <linux/slab.h>  // kmalloc
#include <linux/wait.h>
#include <linux/mutex.h>

extern struct mutex sos_log_lock;
extern wait_queue_head_t  sos_wait_log_queue;
extern char *sos_log_buf;
extern int sos_log_size;
extern unsigned char sos_wait_log_cond;

asmlinkage long sys_get_sos_log(char *buf, unsigned long buf_size) {
    int copy_size = buf_size;

    mutex_lock_interruptible(&sos_log_lock);

    if(sos_log_buf == NULL) {
        mutex_unlock(&sos_log_lock);
        wait_event_interruptible(sos_wait_log_queue, sos_wait_log_cond);
        mutex_lock_interruptible(&sos_log_lock);
    }

    copy_size = sos_log_size < buf_size ? sos_log_size : buf_size;
    copy_to_user(buf, sos_log_buf, copy_size);

    kfree(sos_log_buf);
    sos_log_buf = NULL;
    sos_wait_log_cond = false;

    mutex_unlock(&sos_log_lock);

    return copy_size;
}

