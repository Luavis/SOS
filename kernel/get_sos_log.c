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
#include <linux/spinlock.h>
#include <linux/sos_rbac_role.h>


extern struct mutex sos_log_lock;
extern wait_queue_head_t  sos_wait_log_queue;
extern char *sos_log_buf;
extern int sos_log_size;
extern unsigned char sos_wait_log_cond;
extern rwlock_t sos_role_lock;
extern atomic_t inode_role_flag;
extern struct ls_role *empty_role;
extern char hash_passwd[21];

asmlinkage long
sys_get_sos_log
(char *buf, unsigned long buf_size) {
    int copy_size = buf_size;
    int lock_ret = 0;
    int copy_ret = 0;

    lock_ret = mutex_lock_interruptible(&sos_log_lock);

    if(sos_log_buf == NULL) {
        mutex_unlock(&sos_log_lock);
        wait_event_interruptible(sos_wait_log_queue, sos_wait_log_cond);
        lock_ret = mutex_lock_interruptible(&sos_log_lock);
    }

    copy_size = sos_log_size < buf_size ? sos_log_size : buf_size;
    copy_ret = copy_to_user(buf, sos_log_buf, copy_size);

    if(copy_ret)
        return -ENOMEM;

    kfree(sos_log_buf);
    sos_log_buf = NULL;
    sos_wait_log_cond = false;

    mutex_unlock(&sos_log_lock);

    return copy_size;
}

asmlinkage long
sys_reload_role
(void) {
    struct ls_session_role *session_role = NULL;
    pid_t sid;

    rcu_read_lock();
    sid = pid_vnr(task_session(current));

    printk("session id: %d\n", sid);
    list_for_each_entry(session_role, &ls_session_roles, list) {
        if(session_role->sid == sid && session_role->is_role_manager)
            goto reload;
    }

    return -EPERM; // if not found

reload:
    write_lock(&sos_role_lock);

    ls_trunc_roles();
    ls_print_roles();
    atomic_set(&inode_role_flag, 1);
    ls_init(SOS_ROLE_PATH);

    atomic_set(&inode_role_flag, 0);
    write_unlock(&sos_role_lock);

    // TODO: check permission and return -EACCES
    return 0;
}


asmlinkage long
sys_login_role_manager
(char *passwd) {
    struct ls_session_role *session_role = NULL;
    pid_t sid;

    if(passwd == NULL)
        return -EPERM;

    if(hash_passwd[0] == 0 &&
        hash_passwd[1] == 0 &&
        hash_passwd[2] == 0 &&
        hash_passwd[3] == 0)
            goto out2;

    if(strcmp(passwd, hash_passwd) != 0)
        return -EPERM;

out2:
    rcu_read_lock();
    sid = pid_vnr(task_session(current));

    rcu_read_unlock();

    list_for_each_entry(session_role, &ls_session_roles, list) {
        if(session_role->sid == sid)
            goto out;
    }

    //if session doesn't allocate any role

    session_role = kmalloc(sizeof(struct ls_session_role), GFP_KERNEL);
    session_role->sid = sid;
    list_add(&session_role->list, &ls_session_roles);

out:
    // role manager can access anywhere
    session_role->role = empty_role;
    session_role->is_role_manager = 1;
    return 0;
}


asmlinkage long
sys_logout_role_manager
(void) {
    struct ls_session_role *session_role = NULL;
    pid_t sid;

    rcu_read_lock();

    sid = pid_vnr(task_session(current));

    rcu_read_unlock();

    list_for_each_entry(session_role, &ls_session_roles, list) {
        if(session_role->sid == sid) {
            session_role->is_role_manager = 0;
            break;
        }
    }

    return 0;
}

