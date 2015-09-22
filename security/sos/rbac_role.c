#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sos_rbac_role.h>

struct list_head ls_roles;
unsigned int default_policy = LS_ALLOW;

void
roles_init(void) {
    INIT_LIST_HEAD(&ls_roles);
}

struct ls_role *
create_role(char *name) {

   struct ls_role *role = kmalloc(sizeof(struct ls_role), GFP_KERNEL);

    if(!role) // if low mem
        return NULL;

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
            if(bind_user->uid == uid) {
                return role;
            }
        }
    }

    return NULL;  // if not found return NULL
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

