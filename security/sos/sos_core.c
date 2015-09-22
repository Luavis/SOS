#include <linux/security.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/sos_rbac_role.h>
#include <linux/fs.h>

#define DEBUG_SOS(fmt) printk(fmt)

/*
 * Declare
 */

int sos_lsm_inode_permission(struct inode *inode, int mask);

static struct security_operations sos_lsm_ops = {
    .name = "Sos",

    .inode_permission = sos_lsm_inode_permission  // check permission that it can access or not
};


/*
 * Implementation
 */

static __init int sos_lsm_init(void) {

    // reset current security module
    reset_security_ops();

    DEBUG_SOS("SOS: reset security ops\n");

    // init roles list..
    roles_init();
    DEBUG_SOS("SOS: init_roles\n");

    if(register_security(&sos_lsm_ops)) {
        // make panic when failed to register security module.
        panic("Can not register module");
    }

    DEBUG_SOS("SOS: register security\n");


    return 0;
}

int
sos_lsm_inode_permission
(struct inode *inode, int mask) {

    uid_t current_uid = current_uid().val;

    struct ls_role *role = ls_get_role_by_uid(current_uid);
    unsigned long i_ino = inode->i_ino;

    int retval = ls_is_role_allowed_inode(role, i_ino, mask);

    if(unlikely(retval != 0)) {
        printk("[SOS] denied!!\n");
    }

    return retval;
}

// install security module

security_initcall(sos_lsm_init);

