/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#include <linux/module.h>

/*
 * There is no need to lock the wrapfs_super_info's rwsem as there is no
 * way anyone can have a reference to the superblock at this point in time.
 */
int mmap_option_set = 0;
static int wrapfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct super_block *lower_sb;
	struct path lower_path;
	char *dev_name = (char *) raw_data;
	struct inode *inode;

	if (!dev_name) {
		printk(KERN_ERR
		       "wrapfs: read_super: missing dev_name argument\n");
		err = -EINVAL;
		goto out;
	}

	/* parse lower path */
	err = kern_path(dev_name, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
			&lower_path);
	if (err) {
		printk(KERN_ERR	"wrapfs: error accessing "
		       "lower directory '%s'\n", dev_name);
		goto out;
	}

	/* allocate superblock private data */
	sb->s_fs_info = kzalloc(sizeof(struct wrapfs_sb_info), GFP_KERNEL);
	if (!WRAPFS_SB(sb)) {
		printk(KERN_CRIT "wrapfs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out_free;
	}
	
	WRAPFS_SB(sb)->mmap_option_set = mmap_option_set;
	WRAPFS_SB(sb)->sb_key = NULL;
	
	
	/* set the lower superblock field of upper superblock */
	lower_sb = lower_path.dentry->d_sb;
	atomic_inc(&lower_sb->s_active);
	wrapfs_set_lower_super(sb, lower_sb);

	/* inherit maxbytes from lower file system */
	sb->s_maxbytes = lower_sb->s_maxbytes;

	/*
	 * Our c/m/atime granularity is 1 ns because we may stack on file
	 * systems whose granularity is as good.
	 */
	sb->s_time_gran = 1;

	sb->s_op = &wrapfs_sops;

	/* get a new inode and allocate our root dentry */
	inode = wrapfs_iget(sb, lower_path.dentry->d_inode);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_sput;
	}
	sb->s_root = d_alloc_root(inode);
	if (!sb->s_root) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &wrapfs_dops);

	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (err)
		goto out_freeroot;

	/* if get here: cannot have error */

	/* set the lower dentries for s_root */
	wrapfs_set_lower_path(sb->s_root, &lower_path);

	/*
	 * No need to call interpose because we already have a positive
	 * dentry, which was instantiated by d_alloc_root.  Just need to
	 * d_rehash it.
	 */
	d_rehash(sb->s_root);
	if (!silent)
		printk(KERN_INFO
		       "wrapfs: mounted on top of %s type %s\n",
		       dev_name, lower_sb->s_type->name);
	goto out; /* all is well */

	/* no longer needed: free_dentry_private_data(sb->s_root); */
out_freeroot:
	dput(sb->s_root);
out_iput:
	iput(inode);
out_sput:
	/* drop refs we took earlier */
	atomic_dec(&lower_sb->s_active);
	kfree(WRAPFS_SB(sb));
	sb->s_fs_info = NULL;
out_free:
	path_put(&lower_path);

out:
	return err;
}


int wrapfs_parse_options(char *options)
{
int err = 0;
char *p;
substring_t args[MAX_OPT_ARGS];
unsigned long opt = 0; 
int option;
mmap_option_set = 0;
if (!options) 
{
err = -EINVAL;
goto out;
}

while ((p = strsep(&options, ",")) != NULL) 
{
int token;
if (!*p)
continue;

args[0].to = args[0].from = 0;
token = match_token(p, wrapfs_tokens, args);


switch (token) 
{
	case Opt_mmap:
		mmap_option_set = 1;
		printk("Mmap is set\n");
		break;

	case Opt_debug:
		if (match_int(&args[0], &option)) 
		{
			mmap_option_set = 0;
			err = -EINVAL;
			goto out;
		} 
		printk("Debug is set\n");
		opt = option; 
		printk("Debug Val: %lu\n" , opt);
		break;

	default:
		mmap_option_set = 0;
		printk("In default\n");
		err = -EINVAL;
		goto out;
}
}
out:
return err;
}

struct dentry *wrapfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	void *lower_path_name = (void *) dev_name;
	wrapfs_parse_options(raw_data);
	return mount_nodev(fs_type, flags, lower_path_name,
			   wrapfs_read_super);
}

static struct file_system_type wrapfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= WRAPFS_NAME,
	.mount		= wrapfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_wrapfs_fs(void)
{
	int err;

	pr_info("Registering wrapfs " WRAPFS_VERSION "\n");

	err = wrapfs_init_inode_cache();
	if (err)
		goto out;
	err = wrapfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&wrapfs_fs_type);
out:
	if (err) {
		wrapfs_destroy_inode_cache();
		wrapfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_wrapfs_fs(void)
{
	wrapfs_destroy_inode_cache();
	wrapfs_destroy_dentry_cache();
	unregister_filesystem(&wrapfs_fs_type);
	pr_info("Completed wrapfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs " WRAPFS_VERSION
		   " (http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_wrapfs_fs);
module_exit(exit_wrapfs_fs);
