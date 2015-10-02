#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include "sos_rbac_role.h"

struct list_head ls_roles;
unsigned int default_policy = LS_ALLOW;

// --- UTILITY --- //
unsigned long
binary_to_number
(unsigned char *binary, int len) {
	int i;
	unsigned long number = 0;

	for(i = len - 1; i >= 0; i--) {
		number <<= 8;
		number += binary[i];
	}

	return number;
}

char *
substring
(char *str, int start_pos, int end_pos) {
	char *substr = kmalloc(end_pos - start_pos + 1, GFP_KERNEL);
	memcpy(substr, str + start_pos, end_pos - start_pos);
	substr[end_pos - start_pos] = '\0';

	return substr;
}

void
print_ls_roles
(void) {
	struct ls_role *role = NULL;
	struct ls_role *child_role = NULL;
	struct ls_file_role *file_role = NULL;
	struct ls_network_role *network_role = NULL;
	struct ls_process_role *process_role = NULL;
	struct ls_user *bind_user = NULL;

	list_for_each_entry(role, &ls_roles, list) {
		printk("-------------------------------------------------\n");
		printk("role name : %s\n", role->role_name);
		printk("parent role name : %s\n", role->parent_role != NULL ? role->parent_role->role_name : "NULL");
		printk("child roles name : ");
		list_for_each_entry(child_role, &role->child_roles, child_list) {
			printk("%s ", child_role->role_name);
		}
		printk("\n");

		printk("attr count : %d\n", role->attr_count);

		printk("\t\t<file role>\n");
		list_for_each_entry(file_role, &role->file_roles, list) {
			printk("\t\t - ");
			printk("i_ino : %ld, ", file_role->i_ino);
			printk("u_acc : \\x%02x\n", file_role->u_acc);
		}

		printk("\t\t<network role>\n");
		list_for_each_entry(network_role, &role->network_roles, list) {
			printk("\t\t - ");
			//printk("ip : %s, ", network_role->ip);
			printk("port : %d, ", network_role->port);
			printk("is_allow : %d\n", network_role->is_allow);
		}

		printk("\t\t<process role>\n");
		list_for_each_entry(process_role, &role->process_roles, list) {
			printk("\t\t - ");
			printk("pid : %d, ", process_role->pid);
			printk("is_allow_kill : %d\n", process_role->is_allow_kill);
		}

		printk("\t\t<bind user>\n");
		list_for_each_entry(bind_user, &role->bind_users, list) {
			printk("\t\t - ");
			printk("uid : %d\n", bind_user->uid);
		}

		printk("\t\tEND\n");
	}
}

// --- ROLE --- //
void
roles_init
(void) {
    INIT_LIST_HEAD(&ls_roles);
}

struct ls_role *
ls_create_role
(char *role_name, char *parent_role_name, int attr_count) {
	struct ls_role *role = kmalloc(sizeof(struct ls_role), GFP_KERNEL);
    if(!role)
        return NULL;

	role->role_name = role_name;
	role->parent_role_name = parent_role_name;
	role->parent_role = NULL;
	role->attr_count = attr_count;

    INIT_LIST_HEAD(&role->file_roles);
    INIT_LIST_HEAD(&role->network_roles);
    INIT_LIST_HEAD(&role->process_roles);
    INIT_LIST_HEAD(&role->bind_users);

	INIT_LIST_HEAD(&role->child_roles);
    list_add(&role->list, &ls_roles);

    return role;
}

struct ls_role *
ls_create_role_by_binary
(char *header_data) {
	int offset = 0;
	int attr_count;
	char *role_name;
	char *parent_role_name;

	role_name = substring(header_data, offset + 1, offset + header_data[offset] + 1);
	offset += header_data[offset] + 1;

	parent_role_name = header_data[offset] ? substring(header_data, offset + 1, offset + header_data[offset] + 1) : "";
	offset += header_data[offset] + 1;

	attr_count = binary_to_number(header_data + offset, 4);

	return ls_create_role(role_name, parent_role_name, attr_count);
}

// --- FILE ROLE --- //
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

struct ls_file_role *
ls_create_file_role_by_binary
(struct ls_role *role, char *attr_data) {
	return ls_create_file_role(role, binary_to_number(attr_data + 1, 8), attr_data[9]);
}

// --- NETWORK ROLE --- //
struct ls_network_role *
ls_create_network_role
(struct ls_role *role, unsigned char *ip, unsigned short port, unsigned short is_allow) {
	struct ls_network_role *network_role = kmalloc(sizeof(struct ls_network_role), GFP_KERNEL);
	if(!network_role)
		return NULL;

	network_role->ip = ip;
	network_role->port = port;
	network_role->is_allow = is_allow;

	list_add(&network_role->list, &role->network_roles);

	return network_role;
}

struct ls_network_role *
ls_create_network_role_by_binary
(struct ls_role *role, char *attr_data) {
	return ls_create_network_role(role, substring(attr_data + 1, 1, 5), binary_to_number(attr_data + 5, 2), binary_to_number(attr_data + 7, 2));
}

// --- PROCESS ROLE --- //
struct ls_process_role *
ls_create_process_role
(struct ls_role *role, unsigned int pid, unsigned short is_allow_kill) {
	struct ls_process_role *process_role = kmalloc(sizeof(struct ls_process_role), GFP_KERNEL);
	if(!process_role)
		return NULL;

	process_role->pid = pid;
	process_role->is_allow_kill = is_allow_kill;

	list_add(&process_role->list, &role->process_roles);

	return process_role;
}

struct ls_process_role *
ls_create_process_role_by_binary
(struct ls_role *role, char *attr_data) {
	return ls_create_process_role(role, binary_to_number(attr_data + 1, 4), binary_to_number(attr_data + 5, 2));
}

// --- USER --- //
struct ls_user *
ls_create_user
(struct ls_role *role, uid_t uid) {
	struct ls_user *bind_user = kmalloc(sizeof(struct ls_user), GFP_KERNEL);
	if(!bind_user)
		return NULL;

	bind_user->uid = uid;

	list_add(&bind_user->list, &role->bind_users);

	return bind_user;
}

struct ls_user *
ls_create_user_by_binary
(struct ls_role *role, char *attr_data) {
	return ls_create_user(role, binary_to_number(attr_data + 1, 4));
}

// --- ETC --- ///
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

// --- INITIAL --- //
void
ls_create_object_role_by_binary
(struct ls_role *role, char *attr_data) {
	switch(attr_data[0] & 0xff) {
	case 0x01 : ls_create_file_role_by_binary(role, attr_data); break;
	case 0x02 : ls_create_network_role_by_binary(role, attr_data); break;
	case 0x03 : ls_create_process_role_by_binary(role, attr_data); break;
	case 0xff : ls_create_user_by_binary(role, attr_data); break;
	}
}

void
ls_find_parent_role
(struct ls_role *child_role) {
	struct ls_role *parent_role = NULL;

	list_for_each_entry(parent_role, &ls_roles, list) {
		printk("in loop, child : %s\tparent : %s\n", child_role->role_name, parent_role->role_name);
		if(!strcmp(child_role->parent_role_name, parent_role->role_name)) {
			child_role->parent_role = parent_role;
			list_add(&child_role->child_list, &parent_role->child_roles);

			printk("strcmp success, child : %s\tparent : %s\n", child_role->role_name, parent_role->role_name);
			break;
		}
	}
}

void
ls_init
(void) {
	char header_data[LS_HEADER_SIZE];
	char attr_data[LS_ATTRIBUTE_SIZE];

	struct file *filp;
	struct ls_role * role;

	unsigned int i;

	// file open
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

	filp = filp_open("./data.sos", O_RDWR, S_IRUSR | S_IWUSR);

	if(filp) {
		roles_init();

		while(vfs_read(filp, header_data, LS_HEADER_SIZE, &filp->f_pos)) {
			role = ls_create_role_by_binary(header_data);

			for(i = 0; i < role->attr_count; i++) {
				vfs_read(filp, attr_data, LS_ATTRIBUTE_SIZE, &filp->f_pos);
				ls_create_object_role_by_binary(role, attr_data);
			}
		}

		list_for_each_entry(role, &ls_roles, list) {
			printk("before func, child : %s\n", role->role_name);
			ls_find_parent_role(role);
			printk("after func, child : %s\n", role->role_name);
		}

		filp_close(filp, NULL);

		print_ls_roles();
	}
	else printk("file open error...");

	set_fs(old_fs);
}

int __init init_module(void)
{
	ls_init();

	return 0;
}

void __exit cleanup_module(void)
{
	printk(KERN_INFO "bye\n");
}

