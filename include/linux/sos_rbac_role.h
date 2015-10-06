#ifndef _RBAC_ROLE_H
#define _RBAC_ROLE_H
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/uidgid.h>
#include <linux/types.h>
#include <linux/pid.h>

#define LS_READ_ACCS 1
#define LS_WRITE_ACCS 2
#define LS_EXCUTE_ACCS 4

#define LS_ALLOW 0
#define LS_DENY -EACCES

#define LS_HEADER_SIZE 600
#define LS_ATTRIBUTE_SIZE 10

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
    unsigned int pid;
    unsigned short is_allow_kill;
    struct list_head list;
};

struct ls_user {
    uid_t uid;
    struct list_head list;
};

struct ls_role {
    char *role_name;
	char *parent_role_name;
	unsigned int attr_count;

    struct list_head file_roles;
    struct list_head network_roles;
    struct list_head process_roles;
    struct list_head bind_users;

	struct list_head child_roles;
	struct ls_role * parent_role;

    struct list_head child_list;
    struct list_head list;
};

struct ls_session_role {

    pid_t sid;
    struct ls_role *role;

    struct list_head list;
};

extern struct list_head ls_roles;
extern struct list_head ls_session_roles;

// create role list with name and parent_role name
struct ls_role *
ls_create_role
(char *role_name, char *parent_role_name, int attr_count);

/*
 * Role Objects
 */

// create file role
struct ls_file_role *
ls_create_file_role
(struct ls_role *role, unsigned long i_ino, unsigned char u_acc);

// create network role
struct ls_network_role *
ls_create_network_role
(struct ls_role *role, unsigned char *ip, unsigned short port, unsigned short is_allow);

// create process role
struct ls_process_role *
ls_create_process_role
(struct ls_role *role, unsigned int pid, unsigned short is_allow_kill);

/*
 * Role Subjects
 */

// create binding user role
struct ls_user *
ls_create_user
(struct ls_role *role, uid_t uid);

// rbac utils

void
ls_init
(const char *role_path);

void
roles_init
(void);

void
ls_print_roles
(void);

unsigned int
ls_is_role_allowed_inode
(struct ls_role *role, unsigned long i_ino, unsigned char mode);

struct ls_role *
ls_get_role_by_uid(uid_t uid);

struct ls_role *
ls_get_role_by_sid(pid_t sid);

struct ls_role *
ls_get_role(void);

#endif /* _RBAC_ROLE_H */
