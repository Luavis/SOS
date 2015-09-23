#include <linux/security.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sos_rbac_role.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/string.h>

/*
 * Declare
 */

#define SOS_LOG_SIZE 1024
#define DEBUG_SOS 1


DEFINE_MUTEX(sos_log_lock);
DECLARE_WAIT_QUEUE_HEAD(sos_wait_log_queue);
char *sos_log_buf = NULL;
int sos_log_size;
unsigned char sos_wait_log_cond = false;

int sos_lsm_inode_permission(struct inode *inode, int mask);
void sos_log(char *fmt, ...);

static struct security_operations sos_lsm_ops = {
    .name = "Sos",

    .inode_permission = sos_lsm_inode_permission  // check permission that it can access or not
};


/*
 * Implementation
 */

struct ls_role *role;

static __init int sos_lsm_init(void) {

    // log mutex init
    mutex_init(&sos_log_lock);

    // reset current security module
    reset_security_ops();

    sos_log("SOS: reset security ops\n");

    // init roles list..
    roles_init();

    role = create_role("Test");
    ls_create_file_role(role, 15466509, 0);

    sos_log("SOS: init_roles\n");

    if(register_security(&sos_lsm_ops)) {
        // make panic when failed to register security module.
        panic("Can not register module");
    }

    sos_log("SOS: register security\n");

    return 0;
}

int
sos_lsm_inode_permission
(struct inode *inode, int mask) {

    uid_t current_uid = current_uid().val;
    int retval;

    unsigned long i_ino = inode->i_ino;
    if(current_uid != 1000)
        return 0;

    // struct ls_role *role = ls_get_role_by_uid(current_uid);

    retval = ls_is_role_allowed_inode(role, i_ino, mask);

    if(unlikely(retval != 0)) {
        sos_log("uid %d invalid access to %d\n", current_uid, i_ino);
    }

    return retval;
}

void sos_log(char *msg, ...) {
    va_list ap;
    char *buf = kmalloc(SOS_LOG_SIZE, GFP_KERNEL);
    va_start(ap, msg);

    vscnprintf(buf, SOS_LOG_SIZE, msg, ap);

    va_end(ap);

#ifdef DEBUG_SOS
    printk(buf);
#endif

    // lock inturruptible

    mutex_lock_interruptible(&sos_log_lock);

    if(likely(sos_log_buf != NULL)) {
        kfree(sos_log_buf);  // clean old buffer;
    }

    sos_log_size = strlen(buf);
    sos_log_buf = buf;

    sos_wait_log_cond = true;
    wake_up(&sos_wait_log_queue);
    mutex_unlock(&sos_log_lock);
}

// install security module

security_initcall(sos_lsm_init);

