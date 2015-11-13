#ifndef _RBAC_ROLE_H
#define _RBAC_ROLE_H
#include <linux/hashtable.h>
#include <linux/list.h>
#include <linux/uidgid.h>
#include <linux/types.h>
#include <linux/pid.h>

#define SOS_ROLE_PATH "/etc/data.sos"
#define SOS_INIT_ROLE_PATH "/root/etc/data.sos"

#define LS_READ_ACCS 1
#define LS_WRITE_ACCS 2
#define LS_EXCUTE_ACCS 4

#define CACHE_ROLE 1
#define NOT_CACHE_ROLE 0

#define LS_ALLOW 0
#define LS_DENY -EACCES
#define LS_IS_ALLOWED(X) (X == LS_ALLOW)
#define LS_STATE_STRING(X) (LS_IS_ALLOWED(X) ? "ALLOW" : "DENY")

#define LS_HEADER_SIZE 600
#define LS_ATTRIBUTE_SIZE 10

extern unsigned int default_policy;

// --- OBJECT STRUCTURE --- //
struct ls_file_role {
    unsigned long i_ino;
    unsigned char u_acc;

    struct list_head list;
};

struct ls_network_role {
    unsigned short port;

    unsigned char is_allow_open;

    struct list_head list;
};

enum ls_process_id_type {
    ls_process_uid = 0,
    ls_process_inode
};

struct ls_process_role {
    unsigned long id_value;
    enum ls_process_id_type id_type;

    unsigned char is_allow_kill;
    unsigned char is_allow_trace;
    unsigned char is_allow_setuid;

    struct list_head list;
};

// --- SUBJECT STRUCTURE --- //
struct ls_bind_process {
    unsigned long id_value;
    enum ls_process_id_type id_type;

    struct list_head list;
};

struct ls_bind_user {
    uid_t uid;

    struct list_head list;
};

// --- ROLE --- //
struct ls_role {
    char *role_name;
	char *parent_role_name;
	unsigned int attr_count;

    struct list_head file_roles;
    struct list_head network_roles;
    struct list_head process_roles;

    struct list_head bind_processes;
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
    unsigned char is_role_manager;
};

extern struct list_head ls_roles;
extern struct list_head ls_session_roles;

/*
 * Role list
 */

// create role list with name and parent_role name
struct ls_role *
ls_create_role
(char *role_name, char *parent_role_name, int attr_count);

struct ls_role *
ls_create_role_by_binary
(char *header_data);

/*
 * Role Objects
 */

struct ls_file_role *
ls_create_file_role
(struct ls_role *role, unsigned long i_ino, unsigned char u_acc);

struct ls_file_role *
ls_create_file_role_by_binary
(struct ls_role *role, char *attr_data);

struct ls_network_role *
ls_create_network_role
(struct ls_role *role, unsigned short port, unsigned char is_allow_open);

struct ls_network_role *
ls_create_network_role_by_binary
(struct ls_role *role, char *attr_data);

struct ls_process_role *
ls_create_process_role
(struct ls_role *role, unsigned long id_value, unsigned int id_type,
unsigned char is_allow_kill, unsigned char is_allow_trace, unsigned char is_allow_setuid);

struct ls_process_role *
ls_create_process_role_by_binary
(struct ls_role *role, char *attr_data);

/*
 * Role Subjects
 */

// create binding process role
struct ls_bind_process *
ls_create_bind_process
(struct ls_role *role, unsigned long id_value, unsigned int id_type);

struct ls_bind_process *
ls_create_bind_process_by_binary
(struct ls_role *role, char *attr_data);

// create binding user role
struct ls_bind_user *
ls_create_bind_user
(struct ls_role *role, uid_t uid);

struct ls_bind_user *
ls_create_bind_user_by_binary
(struct ls_role *role, char *attr_data);

// rbac utils

void
ls_init
(const char *role_path);

void
ls_trunc_roles
(void);

void
roles_init
(void);

void
ls_print_roles
(void);

/*
 * Role utils
 */

// init and parse functions for roles
void roles_init(void);

int
ls_is_role_allowed_inode
(struct ls_role *role, unsigned long i_ino, unsigned char mode);

int
ls_is_role_allowed_open_port
(struct ls_role *role, unsigned short port);

int
ls_is_role_allowed_kill
(struct ls_role *role, uid_t uid, unsigned long i_ino);

int
ls_is_role_allowed_trace
(struct ls_role *role, uid_t uid, unsigned long i_ino);

int
ls_is_role_allowed_setuid
(struct ls_role *role, uid_t uid, unsigned long i_ino);

struct ls_role *
ls_get_role_by_uid(uid_t uid);

int
ls_get_role_by_puid
(uid_t uid, struct task_struct *p, struct ls_role **ret_role);

struct ls_role *
ls_get_role_by_sid(pid_t sid);

struct ls_role *
ls_get_role(void);

#endif /* _RBAC_ROLE_H */
