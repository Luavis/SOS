
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/sos_rbac_role.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <asm/thread_info.h>
#include <asm/current.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#define IS_BIT_FLAGGED(DATA, FLAG_BIT) ((DATA & FLAG_BIT) == FLAG_BIT)

struct list_head ls_roles;
struct list_head ls_session_roles;

struct ls_role *default_role;
extern struct ls_role *empty_role;

unsigned int default_policy = LS_ALLOW;
char hash_passwd[21] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

void
ls_find_parent_role
(struct ls_role *child_role);

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

	if(unlikely(substr == NULL))
        return NULL;

    memcpy(substr, str + start_pos, end_pos - start_pos);
	substr[end_pos - start_pos] = '\0';

	return substr;
}

void
ls_print_roles
(void) {
	struct ls_role *role = NULL;
	struct ls_role *child_role = NULL;

	struct ls_file_role *file_role = NULL;
	struct ls_network_role *network_role = NULL;
	struct ls_process_role *process_role = NULL;

    struct ls_bind_process *bind_process = NULL;
	struct ls_bind_user *bind_user = NULL;

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

        printk("\t<OBJECTS>\n");
		printk("\t\t<file roles>\n");
		list_for_each_entry(file_role, &role->file_roles, list) {
			printk("\t\t - ");
			printk("i_ino : %lu, ", file_role->i_ino);
			printk("u_acc : \\x%02x\n", file_role->u_acc);
		}

		printk("\t\t<network roles>\n");
		list_for_each_entry(network_role, &role->network_roles, list) {
			printk("\t\t - ");
			printk("port : %u, ", network_role->port);
			printk("is_allow_open : %s\n", LS_STATE_STRING(network_role->is_allow_open));
		}

		printk("\t\t<process roles>\n");
		list_for_each_entry(process_role, &role->process_roles, list) {
			printk("\t\t - ");
            printk("id_value : %lu, ", process_role->id_value);
            printk("id_type : %s, ", process_role->id_type == ls_process_uid ? "pid" : "inode");
            printk("is_allow_kill : %s, ", LS_STATE_STRING(process_role->is_allow_kill));
            printk("is_allow_trace : %s\n", LS_STATE_STRING(process_role->is_allow_trace));

		}

        printk("\t<SUBJECTS>\n");
        printk("\t\t<bind processes>\n");
        list_for_each_entry(bind_process, &role->bind_processes, list) {
            printk("\t\t - ");
            printk("id_value : %lu, ", bind_process->id_value);
            printk("id_type : %s\n", bind_process->id_type == ls_process_uid ? "pid" : "inode");
        }

		printk("\t\t<bind users>\n");
		list_for_each_entry(bind_user, &role->bind_users, list) {
			printk("\t\t - ");
			printk("uid : %u\n", bind_user->uid);
		}

		printk("\t<END>\n");
	}
}

// --- ROLE --- //
void
roles_init
(void) {
    INIT_LIST_HEAD(&ls_roles);
    INIT_LIST_HEAD(&ls_session_roles);
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

    INIT_LIST_HEAD(&role->bind_processes);
    INIT_LIST_HEAD(&role->bind_users);

	INIT_LIST_HEAD(&role->child_roles);
    list_add(&role->list, &ls_roles);

    if(unlikely(strcmp(role_name, "default") == 0))
        default_role = role; // if role is default set it!
    else if(unlikely(strcmp(role_name, "empty") == 0))
        empty_role = role;
    else
        ls_find_parent_role(role); // if not find parent

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

    if(unlikely(role_name == NULL))
        return NULL;

	offset += header_data[offset] + 1;

	parent_role_name = header_data[offset] ? substring(header_data, offset + 1, offset + header_data[offset] + 1) : "";

    if(unlikely(role_name == NULL))
        return NULL;

    offset += header_data[offset] + 1;

	attr_count = binary_to_number(header_data + offset, 4);

    if(unlikely(attr_count < 0))
        return NULL;

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
(struct ls_role *role, unsigned short port, unsigned char is_allow_open) {
	struct ls_network_role *network_role = kmalloc(sizeof(struct ls_network_role), GFP_KERNEL);
	if(!network_role)
		return NULL;

	network_role->port = port;
	network_role->is_allow_open = is_allow_open;

	list_add(&network_role->list, &role->network_roles);

	return network_role;
}

struct ls_network_role *
ls_create_network_role_by_binary
(struct ls_role *role, char *attr_data) {
	return ls_create_network_role(role, binary_to_number(attr_data + 1, 2), attr_data[3]);
}

// --- PROCESS ROLE --- //
struct ls_process_role *
ls_create_process_role
(struct ls_role *role, unsigned long id_value, unsigned int id_type,
unsigned char is_allow_kill, unsigned char is_allow_trace, unsigned char is_allow_setuid) {
	struct ls_process_role *process_role = kmalloc(sizeof(struct ls_process_role), GFP_KERNEL);
	if(!process_role)
		return NULL;

    switch(id_type) {
    case ls_process_uid : process_role->id_type = ls_process_uid; break;
    case ls_process_inode : process_role->id_type = ls_process_inode; break;
    default : return NULL;
    }

    process_role->id_value = id_value;
	process_role->is_allow_kill = is_allow_kill;
    process_role->is_allow_trace = is_allow_trace;
    process_role->is_allow_setuid = is_allow_setuid;
	list_add(&process_role->list, &role->process_roles);

	return process_role;
}

struct ls_process_role *
ls_create_process_role_by_binary
(struct ls_role *role, char *attr_data) {
	return ls_create_process_role(
        role,
        binary_to_number(attr_data + 1, 8),
        IS_BIT_FLAGGED(attr_data[9], 0x08),
        IS_BIT_FLAGGED(attr_data[9], 0x04),
        IS_BIT_FLAGGED(attr_data[9], 0x02),
        IS_BIT_FLAGGED(attr_data[9], 0x01));
}

// --- BIND PROCESS --- //
struct ls_bind_process *
ls_create_bind_process
(struct ls_role *role, unsigned long id_value, unsigned int id_type) {
    struct ls_bind_process *bind_process = kmalloc(sizeof(struct ls_bind_process), GFP_KERNEL);
    if(!bind_process)
        return NULL;

    switch(id_type) {
    case ls_process_uid : bind_process->id_type = ls_process_uid; break;
    case ls_process_inode : bind_process->id_type = ls_process_inode; break;
    default : return NULL;
    }

    bind_process->id_value = id_value;

    list_add(&bind_process->list, &role->bind_processes);

    return bind_process;
}

struct ls_bind_process *
ls_create_bind_process_by_binary
(struct ls_role *role, char *attr_data) {
    return ls_create_bind_process(
        role,
        binary_to_number(attr_data + 1, 8),
        IS_BIT_FLAGGED(attr_data[9], 0x01));
}

// --- BIND USER --- //
struct ls_bind_user *
ls_create_bind_user
(struct ls_role *role, uid_t uid) {
	struct ls_bind_user *bind_user = kmalloc(sizeof(struct ls_bind_user), GFP_KERNEL);
	if(!bind_user)
		return NULL;

	bind_user->uid = uid;

	list_add(&bind_user->list, &role->bind_users);

	return bind_user;
}

struct ls_bind_user *
ls_create_bind_user_by_binary
(struct ls_role *role, char *attr_data) {
	return ls_create_bind_user(role, binary_to_number(attr_data + 1, 4));
}

// --- rbac utils --- ///
struct ls_role *
ls_get_role_by_uid(uid_t uid) {
    struct ls_role *role = NULL;
    struct ls_bind_user *bind_user = NULL;

    list_for_each_entry(role, &ls_roles, list) {
       list_for_each_entry(bind_user, &role->bind_users, list) {
            // check user id
            if(bind_user->uid == uid)
                return role;
        }
    }

    return default_role;  // if not found return NULL
}


int
ls_get_role_by_puid
(uid_t uid, struct task_struct *p, struct ls_role **ret_role) {
    struct ls_role *role = NULL;
    struct ls_bind_user *bind_user = NULL;
    struct ls_bind_process *bind_process = NULL;
    struct ls_role *inode_role = NULL;
    struct file *exe_file;
    struct mm_struct *mm;
    pid_t pid = p->pid;
    unsigned long i_ino = 0;

    *ret_role = default_role;

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
    i_ino = exe_file->f_inode->i_ino;
    mmput(mm);

    list_for_each_entry(role, &ls_roles, list) {
       list_for_each_entry(bind_user, &role->bind_users, list) {
            // check user id
            if(bind_user->uid == uid) {
                *ret_role = role;
                return CACHE_ROLE;
            }
        }

        list_for_each_entry(bind_process, &role->bind_processes, list) {
            if((bind_process->id_type == ls_process_uid)
                    && bind_process->id_value == pid)
                *ret_role = role;
            else if((bind_process->id_type == ls_process_inode)
                    && bind_process->id_value == i_ino)
                inode_role = role;
        }
    }

    if(likely(inode_role != NULL))
        *ret_role = inode_role;

    return NOT_CACHE_ROLE;  // if not found return NULL
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
    int cache_role = NOT_CACHE_ROLE;

    rcu_read_lock(); // rcu read lock for current processor status

    // search session based on cred
    sid = pid_vnr(task_session(current));
    uid = current->cred->uid.val;

    if(s_role && s_role->sid == sid)
        retval = s_role->role;

    if(!retval) {
        retval = ls_get_role_by_sid(sid);

        if(!retval) {
            cache_role = ls_get_role_by_puid(uid, current, &retval);

            if(cache_role && retval) {
                s_role = kmalloc(sizeof(struct ls_session_role), GFP_KERNEL);
                s_role->sid = sid;
                s_role->role = retval;
                s_role->is_role_manager = 0;

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

int
ls_is_role_allowed_inode
(struct ls_role *role, unsigned long i_ino, unsigned char mode) {
    struct ls_file_role *file_role = NULL;

    if(unlikely(role == NULL))
        return default_policy;

    list_for_each_entry(file_role, &role->file_roles, list) {
        if(file_role->i_ino == i_ino)
            return (file_role->u_acc & mode) != 0 ? LS_ALLOW : LS_DENY;
    }

    if(role->parent_role != NULL)
        return ls_is_role_allowed_inode(role->parent_role, i_ino, mode);
    else
        return default_policy;
}

int
ls_is_role_allowed_open_port
(struct ls_role *role, unsigned short port) {
    struct ls_network_role *network_role = NULL;

    if(unlikely(role == NULL))
        return default_policy;

    list_for_each_entry(network_role, &role->network_roles, list) {

        if(network_role->port == port)
            return LS_IS_ALLOWED(network_role->is_allow_open) ? LS_ALLOW : LS_DENY;
    }

    if(role->parent_role != NULL)
        return ls_is_role_allowed_open_port(role->parent_role, port);
    else
        return default_policy;
}

int
ls_is_role_allowed_kill
(struct ls_role *role, uid_t uid, unsigned long i_ino) {
    struct ls_process_role *process_role = NULL;
    unsigned int retval = INT_MAX;

    if(unlikely(role == NULL))
        return default_policy;

    list_for_each_entry(process_role, &role->process_roles, list) {
        if((process_role->id_type == ls_process_uid)
               && process_role->id_value == uid)
            return process_role->is_allow_kill;
        else if((process_role->id_type == ls_process_inode)
                && process_role->id_value == i_ino)
            retval = process_role->is_allow_kill;
    }

    if(retval != INT_MAX)
        return LS_IS_ALLOWED(retval) ? LS_ALLOW : LS_DENY;

    if(role->parent_role != NULL)
        return ls_is_role_allowed_kill(role->parent_role, uid, i_ino);
    else
        return default_policy;
}

int
ls_is_role_allowed_trace
(struct ls_role *role, uid_t uid, unsigned long i_ino) {
    struct ls_process_role *process_role = NULL;
    unsigned int retval = INT_MAX;

    if(unlikely(role == NULL))
        return default_policy;

    list_for_each_entry(process_role, &role->process_roles, list) {

        // if same uid exist in role return it now
        if((process_role->id_type == ls_process_uid)
                && process_role->id_value == uid)
            return process_role->is_allow_trace;
        // if found by inode return it later
        else if((process_role->id_type == ls_process_inode)
                && process_role->id_value == i_ino)
            retval = process_role->is_allow_trace;
    }

    if(retval != INT_MAX)
        return LS_IS_ALLOWED(retval) ? LS_ALLOW : LS_DENY;

    if(role->parent_role != NULL)
        return ls_is_role_allowed_trace(role->parent_role, uid, i_ino);
    else
        return default_policy;
}

int
ls_is_role_allowed_setuid
(struct ls_role *role, uid_t uid, unsigned long i_ino) {
    struct ls_process_role *process_role = NULL;
    unsigned int retval = INT_MAX;

    if(unlikely(role == NULL))
        return default_policy;

    list_for_each_entry(process_role, &role->process_roles, list) {

        // if same uid exist in role return it now
        if((process_role->id_type == ls_process_uid)
                && process_role->id_value == uid)
            return process_role->is_allow_setuid;
        // if found by inode return it later
        else if((process_role->id_type == ls_process_inode)
                && process_role->id_value == i_ino)
            retval = process_role->is_allow_setuid;
    }

    if(retval != INT_MAX)
        return LS_IS_ALLOWED(retval) ? LS_ALLOW : LS_DENY;

    if(role->parent_role != NULL)
        return ls_is_role_allowed_setuid(role->parent_role, uid, i_ino);
    else
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

    case 0xfe : ls_create_bind_process_by_binary(role, attr_data); break;
	case 0xff : ls_create_bind_user_by_binary(role, attr_data); break;
	}
}

void
ls_find_parent_role
(struct ls_role *child_role) {
	struct ls_role *parent_role = NULL;

    if(child_role == default_role || child_role == empty_role)
        return; // pass default or empty role

    // when child_role doesn't have parent role name set it default
    if(child_role->parent_role_name == NULL) {
        child_role->parent_role_name = "default";
        child_role->parent_role = default_role;
        return;
    }

	list_for_each_entry(parent_role, &ls_roles, list) {
		if(!strcmp(child_role->parent_role_name, parent_role->role_name)) {
			child_role->parent_role = parent_role;
			list_add(&child_role->child_list, &parent_role->child_roles);
			break;
		}
    }

    // when can't find parent role by name replace it with default
    if(child_role->parent_role == NULL) {
        child_role->parent_role_name = "default";
        child_role->parent_role = default_role;
    }
}

void
ls_init
(const char *role_path) {
	char header_data[LS_HEADER_SIZE];
	char attr_data[LS_ATTRIBUTE_SIZE];

	struct file *filp;
	struct ls_role * role;

	unsigned int i;

	// file open
	mm_segment_t old_fs = get_fs();
	set_fs(KERNEL_DS);

	filp = filp_open(role_path, O_RDONLY, S_IRUSR);

	if(likely(!IS_ERR(filp))) {
        // read password
        vfs_read(filp, hash_passwd, 20, &filp->f_pos);

		while(vfs_read(filp, header_data, LS_HEADER_SIZE, &filp->f_pos)) {
			role = ls_create_role_by_binary(header_data);
            if(unlikely(role == NULL))
                panic("SOS: data.sos is invalid\n");

			for(i = 0; i < role->attr_count; i++) {
				vfs_read(filp, attr_data, LS_ATTRIBUTE_SIZE, &filp->f_pos);
				ls_create_object_role_by_binary(role, attr_data);
			}
		}

		filp_close(filp, NULL);
	}
	else {
        ls_create_role("default", NULL, 0);
        printk("SOS: Unknown file pointer:  %p\n", filp);
        printk("SOS: file open error...\n");
    }

	set_fs(old_fs);
}


void
ls_trunc_roles
(void) {

    struct ls_role *role;
    struct ls_role *n_role;

    struct ls_file_role *file_role;
    struct ls_file_role *n_file_role;

    struct ls_network_role *network_role;
    struct ls_network_role *n_network_role;

    struct ls_process_role *process_role;
    struct ls_process_role *n_process_role;

    struct ls_bind_process *bind_process;
    struct ls_bind_process *n_bind_process;

    struct ls_bind_user *bind_user;
    struct ls_bind_user *n_bind_user;
    struct ls_session_role *session_role;
    struct ls_session_role *n_session_role;

    list_for_each_entry_safe(role, n_role, &ls_roles, list) {
        list_for_each_entry_safe(file_role, n_file_role, &role->file_roles, list) {
            list_del(&file_role->list);
            kfree(file_role);
            file_role = NULL;
        }

        list_for_each_entry_safe(network_role, n_network_role, &role->network_roles, list) {
            list_del(&network_role->list);
            kfree(network_role);
            network_role = NULL;
        }

        list_for_each_entry_safe(process_role, n_process_role, &role->process_roles, list) {
            list_del(&process_role->list);
            kfree(process_role);
            process_role = NULL;
        }

        list_for_each_entry_safe(bind_process, n_bind_process, &role->bind_processes, list) {
            list_del(&bind_process->list);
            kfree(bind_process);
            bind_process = NULL;
        }

        list_for_each_entry_safe(bind_user, n_bind_user, &role->bind_users, list) {
            list_del(&bind_user->list);
            kfree(bind_user);
            bind_user = NULL;
        }

        // kfree(role->role_name);
        list_del(&role->list);
        kfree(role);
    }

    list_for_each_entry_safe(session_role, n_session_role, &ls_session_roles, list) {
        list_del(&session_role->list);
        kfree(session_role);
    }

    ls_create_role("empty", NULL, 0);
}

