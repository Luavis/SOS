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
#include <linux/list.h>
#include <linux/socket.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/spinlock.h>
#include <linux/binfmts.h>

/*
 * Declare
 */

#define SOS_LOG_SIZE 1024
#define DEBUG_SOS 1

DEFINE_RWLOCK(sos_role_lock);
DEFINE_MUTEX(sos_log_lock);
DECLARE_WAIT_QUEUE_HEAD(sos_wait_log_queue);

char *sos_log_buf = NULL;
int sos_log_size;
unsigned char sos_wait_log_cond = false;
atomic_t inode_role_flag;
struct ls_role *empty_role;

int
sos_load_role
(void);

int
sos_lsm_prepare_creds
(struct cred* cred, const struct cred *old, gfp_t gfp);

int
sos_lsm_task_kill
(struct task_struct *p, struct siginfo *info, int sig, u32 secid);

int
sos_lsm_task_trace
(struct task_struct *p, unsigned int mode);

int
sos_lsm_socket_bind
(struct socket *sock, struct sockaddr *address, int addrlen);

int
sos_lsm_inode_permission
(struct inode *inode, int mask);

int
sos_lsm_bprm_check
(struct linux_binprm *bprm);

int
sos_task_fix_setuid
(struct cred *new, const struct cred *old, int flags);

int
sos_inode_unlink
(struct inode *dir, struct dentry *dentry);

void
sos_log
(char *fmt, ...);

static struct security_operations sos_lsm_ops = {
    .name = "Sos",
    // cred created
    .cred_prepare = sos_lsm_prepare_creds,
    // task get killed
    .bprm_check_security = sos_lsm_bprm_check,
    .ptrace_access_check = sos_lsm_task_trace,
    .task_kill = sos_lsm_task_kill,
    // socket created
    .socket_bind  = sos_lsm_socket_bind,
    // check permission that it can access or not
    .inode_permission = sos_lsm_inode_permission,
    .inode_unlink = sos_inode_unlink,
    .task_fix_setuid = sos_task_fix_setuid
};

int sos_load_role(void) {
    read_lock(&sos_role_lock);
    printk("SOS: load role\n");
    ls_init(SOS_INIT_ROLE_PATH);
#ifdef DEBUG_SOS
    ls_print_roles();
#endif

    read_unlock(&sos_role_lock);
    return 0;
}

/*
 * Implementation
 */

static __init int sos_lsm_init(void) {

    // log mutex init
    mutex_init(&sos_log_lock);

    // reset current security module
    reset_security_ops();

    sos_log("SOS: reset security ops\n");

    read_lock(&sos_role_lock);
    // init roles list..
    roles_init();
    read_unlock(&sos_role_lock);

    sos_log("SOS: init_roles\n");

    ls_create_role("empty", NULL, 0);

    if(register_security(&sos_lsm_ops))
        // make panic when failed to register security module.
        panic("Can not register module\n");

    sos_log("SOS: register security\n");

    return 0;
}

int
sos_lsm_inode_permission
(struct inode *inode, int mask) {

    unsigned long i_ino = inode->i_ino;
    int retval = 0;
    struct ls_role *role;

    if(atomic_read(&inode_role_flag) == 1) // pass if status is reloading role
        return 0;

    read_lock(&sos_role_lock);
    role = ls_get_role();
    read_unlock(&sos_role_lock);

    retval = ls_is_role_allowed_inode(role, i_ino, mask);

    if(unlikely(retval != 0))
        sos_log("invalid access to %d\n", i_ino);

    return retval;
}

int
sos_lsm_socket_bind
(struct socket *sock, struct sockaddr *address, int addrlen) {
    unsigned char port_1b = address->sa_data[0];
    unsigned char port_2b = address->sa_data[1];
    unsigned short port = (port_1b << 8) | port_2b;
    int retval = 0;

    struct ls_role *role;

    read_lock(&sos_role_lock);
    role = ls_get_role();
    read_unlock(&sos_role_lock);

    retval = ls_is_role_allowed_open_port(role, port);

    if(unlikely(retval != 0))
        printk("incalid acc to port %d\n", port);
        // sos_log("invalid access to port %d\n", port);

    return retval;
}

int
sos_lsm_task_kill
(struct task_struct *p, struct siginfo *info, int sig, u32 secid) {
    struct mm_struct *mm;
	struct file *exe_file;
    struct ls_role *role;
    int retval = default_policy;

    read_lock(&sos_role_lock);
    role = ls_get_role();
    read_unlock(&sos_role_lock);

	mm = get_task_mm(p);
	// put_task_struct(p);
	if (!mm)
        return retval;

    exe_file = get_mm_exe_file(mm);
	mmput(mm);
	if (exe_file) {
        retval = ls_is_role_allowed_kill(role, p->cred->uid.val, exe_file->f_inode->i_ino);

	}
    if(unlikely(retval != 0)) {
        sos_log("invalid kill to uid %d, inode %d\n", p->cred->uid.val, exe_file->f_inode->i_ino);
        return -EPERM;
    }

    return retval;
}

int
sos_lsm_bprm_check
(struct linux_binprm *bprm) {
    int retval = default_policy;
    struct file *exe_file;
    struct ls_role *role;
    uid_t uid = current->cred->uid.val;

    if(unlikely((int)current->cred->security != 0x00 || (int)bprm->cred->security != 0x00)) {
        role = ls_get_role();
        exe_file = bprm->file;
        printk(KERN_DEBUG "detect 0xff\n");

        if(exe_file) {
	    uid = (int)current->cred->security;

            if(uid == 0)
	        uid = (int)bprm->cred->security;
            printk(KERN_DEBUG "exe checked uid: %d, inode %d\n", uid, exe_file->f_inode->i_ino);
            retval = ls_is_role_allowed_setuid(
                role, uid,
                exe_file->f_inode->i_ino
            );
            return retval;
        }
    }

    if(current->ptrace & PT_PTRACED) {
        role = ls_get_role();
        exe_file = bprm->file;

        if(exe_file) {
            retval = ls_is_role_allowed_trace(
                role, uid,
                exe_file->f_inode->i_ino
            );
        }
    }
    else
        goto out;

    if(unlikely(retval != 0)) {
        sos_log("invalid trace me to uid %d, inode %d\n", uid, exe_file->f_inode->i_ino);
        return -EPERM;
    }

out:
    return retval;
}

int
sos_lsm_task_trace
(struct task_struct *p, unsigned int mode) {
    struct mm_struct *mm;
	struct file *exe_file;
    struct ls_role *role;

    int retval = default_policy;

    read_lock(&sos_role_lock);
    role = ls_get_role();
    read_unlock(&sos_role_lock);

    mm = p->mm; // get_task_mm(p);

    if (!mm)
        return default_policy;
    else {
        if(p->flags & PF_KTHREAD)
            return default_policy;
        else
            atomic_inc(&mm->mm_users);
    }

    exe_file = get_mm_exe_file(mm);
	mmput(mm);
	if (exe_file) {
        retval = ls_is_role_allowed_trace(role, p->cred->uid.val, exe_file->f_inode->i_ino);
	}

    if(unlikely(retval != 0)) {
        sos_log("invalid trace to uid %d, inode %d\n", p->cred->uid.val, exe_file->f_inode->i_ino);
        return -EPERM;
    }
    return retval;
}

int
sos_lsm_prepare_creds
(struct cred *cred, const struct cred *old, gfp_t gfp) {

    return 0;
}

int
sos_task_fix_setuid
(struct cred *new, const struct cred *old, int flags) {

    if(flags & LSM_SETID_ID) {
        printk(KERN_DEBUG "SOS: call old %d setuid %d to %d\n", old->security, old->uid.val, new->uid.val);
	if(old->security != 0)
            new->security = old->security;
	else
            new->security = (void *)old->uid.val;
    }

    return 0;
}

int
sos_inode_unlink
(struct inode *dir, struct dentry *dentry) {

    unsigned long i_ino;
    int retval = 0;

    struct ls_role *role;

    if(unlikely(dentry->d_inode == NULL))
        return 0;
    i_ino = dentry->d_inode->i_ino;

    if(atomic_read(&inode_role_flag) == 1) // pass if status is reloading role
        return 0;

    read_lock(&sos_role_lock);
    role = ls_get_role();
    read_unlock(&sos_role_lock);

    retval = ls_is_role_allowed_inode(role, i_ino, 2); // check write permission

    if(unlikely(retval != 0))
        sos_log("invalid access to %d\n", i_ino);

    return retval;
}

void
sos_log
(char *msg, ...) {
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

