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


asmlinkage long sys_get_sos_log(char *buf, unsigned long buf_size) {


}

