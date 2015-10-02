#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/uidgid.h>
#include <linux/init.h>
#include <linux/sos_rbac_role.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <asm/thread_info.h>
#include <asm/current.h>


struct list_head ls_roles;
struct list_head ls_session_roles;

struct ls_role *default_role;

unsigned int default_policy = LS_ALLOW;

void
roles_init(void) {
    INIT_LIST_HEAD(&ls_roles);
    printk("SOS session list init\n");
    INIT_LIST_HEAD(&ls_session_roles);
}

struct ls_role *
create_role(char *name) {

   struct ls_role *role = kmalloc(sizeof(struct ls_role), GFP_KERNEL);

    if(!role) // if low mem
        return NULL;

    if(strcmp(name, "default") == 0)
        default_role = role;

    role->role_name = name;
    INIT_LIST_HEAD(&role->file_roles);
    INIT_LIST_HEAD(&role->network_roles);
    INIT_LIST_HEAD(&role->processor_roles);
    INIT_LIST_HEAD(&role->bind_users);

    list_add(&role->list, &ls_roles);
    return role;
}

struct ls_file_role *
ls_create_file_role
(struct ls_role *role, unsigned long i_ino, unsigned char u_acc) {
    struct ls_file_role *file_role = kmalloc(sizeof(struct ls_file_role), GFP_KERNEL);
    if(!file_role)
        return NULL;

    file_role->i_ino = i_ino;
    file_role->u_acc = u_acc;

    list_add(&file_role->list, &role->file_roles);

    return file_role;
}

struct ls_role *
ls_get_role_by_uid(uid_t uid) {
    struct ls_role *role = NULL;
    struct ls_user *bind_user = NULL;

    list_for_each_entry(role, &ls_roles, list) {
       list_for_each_entry(bind_user, &role->bind_users, list) {
            // check user id
            if(bind_user->uid == uid)
                return role;
        }
    }

    return default_role;  // if not found return NULL
}

struct ls_role *
ls_get_role_by_sid(pid_t sid) {

    struct ls_session_role *session_role = NULL;

    list_for_each_entry(session_role, &ls_session_roles, list) {
        if(session_role->sid == sid)
            return session_role->role;
    }

    return NULL;
}

struct ls_role *
ls_get_role() {
    struct ls_session_role *s_role = NULL;
    struct ls_role * retval = NULL;
    pid_t sid;
    uid_t uid;

    rcu_read_lock(); // rcu read lock for current processor status

    s_role = current->cred->security;

    // search session based on cred
    sid = pid_vnr(task_session(current));
    uid = current->cred->uid.val;

    if(s_role && s_role->sid == sid)
        retval = s_role->role;

    if(!retval) {
        retval = ls_get_role_by_sid(sid);

        if(!retval) {
            retval = ls_get_role_by_uid(uid);

            if(retval && retval != default_role) {
                s_role = kmalloc(sizeof(struct ls_session_role), GFP_KERNEL);
                s_role->sid = sid;
                s_role->role = retval;

                list_add(&s_role->list, &ls_session_roles);
            }
        }
        else {
            // current->cred->security = retval;
        }
    }


    rcu_read_unlock();

    return retval;
}

unsigned int
ls_is_role_allowed_inode
(struct ls_role *role, unsigned long i_ino, unsigned char mode) {
    struct ls_file_role *file_role = NULL;

    if(role == NULL)
        return default_policy;

    list_for_each_entry(file_role, &role->file_roles, list) {
        if(file_role->i_ino == i_ino)
            return (file_role->u_acc & mode) != 0 ? LS_ALLOW : LS_DENY;
    }

    return default_policy;
}

