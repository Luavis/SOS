// rbac_role.h

// RBAC(role based access control) roles..
#ifndef _RBAC_ROLE_H
#define _RBAC_ROLE_H
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/uidgid.h>
#include <linux/types.h>

#define LS_READ_ACCS 1
#define LS_WRITE_ACCS 2
#define LS_EXCUTE_ACCS 4

#define LS_ALLOW 0
#define LS_DENY -EACCES

#define LS_ROLES_SIZE 10

extern unsigned int default_policy;


struct ls_file_role {
    unsigned long i_ino;
    unsigned char u_acc;
    struct list_head list;
};

struct ls_network_role {
    unsigned char *ip;
    unsigned short port;
    unsigned short is_allow;
    struct list_head list;
};

struct ls_process_role {
    unsigned long pid;
    unsigned short is_allow_kill;
    struct list_head list;
};

struct ls_user {
    uid_t uid;
    struct list_head list;
};

struct ls_role {
    char *role_name;

    struct list_head file_roles;
    struct list_head network_roles;
    struct list_head processor_roles;
    struct list_head bind_users;

    struct list_head list;
};

extern struct list_head ls_roles;

void roles_init(void);
struct ls_role *create_role(char *name);


////////////// About File ////////////////

struct ls_file_role *
ls_create_file_role
(struct ls_role *role, unsigned long i_ino, unsigned char u_acc);

// Check user is allowed to access inode
unsigned int
ls_is_role_allowed_inode
(struct ls_role *role, unsigned long i_ino, unsigned char mode);

struct ls_role *
ls_get_role_by_uid(uid_t uid);

#endif /* _RBAC_ROLE_H */
