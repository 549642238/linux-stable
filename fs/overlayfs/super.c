// SPDX-License-Identifier: GPL-2.0-only
/*
 *
 * Copyright (C) 2011 Novell Inc.
 */

#include <uapi/linux/magic.h>
#include <linux/fs.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/mount.h>
#include <linux/parser.h>
#include <linux/module.h>
#include <linux/statfs.h>
#include <linux/seq_file.h>
#include <linux/posix_acl_xattr.h>
#include <linux/exportfs.h>
#include "overlayfs.h"

MODULE_AUTHOR("Miklos Szeredi <miklos@szeredi.hu>");
MODULE_DESCRIPTION("Overlay filesystem");
MODULE_LICENSE("GPL");


struct ovl_dir_cache;

#define OVL_MAX_STACK 500

static bool ovl_redirect_dir_def = IS_ENABLED(CONFIG_OVERLAY_FS_REDIRECT_DIR);
module_param_named(redirect_dir, ovl_redirect_dir_def, bool, 0644);
MODULE_PARM_DESC(redirect_dir,
		 "Default to on or off for the redirect_dir feature");

static bool ovl_redirect_always_follow =
	IS_ENABLED(CONFIG_OVERLAY_FS_REDIRECT_ALWAYS_FOLLOW);
module_param_named(redirect_always_follow, ovl_redirect_always_follow,
		   bool, 0644);
MODULE_PARM_DESC(redirect_always_follow,
		 "Follow redirects even if redirect_dir feature is turned off");

static bool ovl_index_def = IS_ENABLED(CONFIG_OVERLAY_FS_INDEX);
module_param_named(index, ovl_index_def, bool, 0644);
MODULE_PARM_DESC(index,
		 "Default to on or off for the inodes index feature");

static bool ovl_nfs_export_def = IS_ENABLED(CONFIG_OVERLAY_FS_NFS_EXPORT);
module_param_named(nfs_export, ovl_nfs_export_def, bool, 0644);
MODULE_PARM_DESC(nfs_export,
		 "Default to on or off for the NFS export feature");

static bool ovl_xino_auto_def = IS_ENABLED(CONFIG_OVERLAY_FS_XINO_AUTO);
module_param_named(xino_auto, ovl_xino_auto_def, bool, 0644);
MODULE_PARM_DESC(xino_auto,
		 "Auto enable xino feature");

static void ovl_entry_stack_free(struct ovl_entry *oe)
{
	unsigned int i;

	for (i = 0; i < oe->numlower; i++)
		dput(oe->lowerstack[i].dentry);
}

static bool ovl_metacopy_def = IS_ENABLED(CONFIG_OVERLAY_FS_METACOPY);
module_param_named(metacopy, ovl_metacopy_def, bool, 0644);
MODULE_PARM_DESC(metacopy,
		 "Default to on or off for the metadata only copy up feature");

static void ovl_dentry_release(struct dentry *dentry)
{
	struct ovl_entry *oe = dentry->d_fsdata;

	if (oe) {
		ovl_entry_stack_free(oe);
		kfree_rcu(oe, rcu);
	}
}

static struct dentry *ovl_d_real(struct dentry *dentry,
				 const struct inode *inode)
{
	struct dentry *real;

	/* It's an overlay file */
	if (inode && d_inode(dentry) == inode)
		return dentry;

	if (!d_is_reg(dentry)) {
		if (!inode || inode == d_inode(dentry))
			return dentry;
		goto bug;
	}

	real = ovl_dentry_upper(dentry);
	if (real && (inode == d_inode(real)))
		return real;

	if (real && !inode && ovl_has_upperdata(d_inode(dentry)))
		return real;

	real = ovl_dentry_lowerdata(dentry);
	if (!real)
		goto bug;

	/* Handle recursion */
	real = d_real(real, inode);

	if (!inode || inode == d_inode(real))
		return real;
bug:
	WARN(1, "ovl_d_real(%pd4, %s:%lu): real dentry not found\n", dentry,
	     inode ? inode->i_sb->s_id : "NULL", inode ? inode->i_ino : 0);
	return dentry;
}

static int ovl_dentry_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	unsigned int i;
	int ret = 1;

	for (i = 0; i < oe->numlower; i++) {
		struct dentry *d = oe->lowerstack[i].dentry;

		if (d->d_flags & DCACHE_OP_REVALIDATE) {
			ret = d->d_op->d_revalidate(d, flags);
			if (ret < 0)
				return ret;
			if (!ret) {
				if (!(flags & LOOKUP_RCU))
					d_invalidate(d);
				return -ESTALE;
			}
		}
	}
	return 1;
}

static int ovl_dentry_weak_revalidate(struct dentry *dentry, unsigned int flags)
{
	struct ovl_entry *oe = dentry->d_fsdata;
	unsigned int i;
	int ret = 1;

	for (i = 0; i < oe->numlower; i++) {
		struct dentry *d = oe->lowerstack[i].dentry;

		if (d->d_flags & DCACHE_OP_WEAK_REVALIDATE) {
			ret = d->d_op->d_weak_revalidate(d, flags);
			if (ret <= 0)
				break;
		}
	}
	return ret;
}

static const struct dentry_operations ovl_dentry_operations = {
	.d_release = ovl_dentry_release,
	.d_real = ovl_d_real,
};

static const struct dentry_operations ovl_reval_dentry_operations = {
	.d_release = ovl_dentry_release,
	.d_real = ovl_d_real,
	.d_revalidate = ovl_dentry_revalidate,
	.d_weak_revalidate = ovl_dentry_weak_revalidate,
};

static struct kmem_cache *ovl_inode_cachep;

static struct inode *ovl_alloc_inode(struct super_block *sb)
{
	struct ovl_inode *oi = kmem_cache_alloc(ovl_inode_cachep, GFP_KERNEL);

	if (!oi)
		return NULL;

	oi->cache = NULL;
	oi->redirect = NULL;
	oi->version = 0;
	oi->flags = 0;
	oi->__upperdentry = NULL;
	oi->lower = NULL;
	oi->lowerdata = NULL;
	mutex_init(&oi->lock);

	return &oi->vfs_inode;
}

static void ovl_free_inode(struct inode *inode)
{
	struct ovl_inode *oi = OVL_I(inode);

	kfree(oi->redirect);
	mutex_destroy(&oi->lock);
	kmem_cache_free(ovl_inode_cachep, oi);
}

static void ovl_destroy_inode(struct inode *inode)
{
	struct ovl_inode *oi = OVL_I(inode);

	dput(oi->__upperdentry);
	iput(oi->lower);
	if (S_ISDIR(inode->i_mode))
		ovl_dir_cache_free(inode);
	else
		iput(oi->lowerdata);
}

static void ovl_free_fs(struct ovl_fs *ofs)
{
	unsigned i;

	iput(ofs->workbasedir_trap);
	iput(ofs->indexdir_trap);
	iput(ofs->workdir_trap);
	iput(ofs->upperdir_trap);
	dput(ofs->indexdir);
	dput(ofs->workdir);
	if (ofs->workdir_locked)
		ovl_inuse_unlock(ofs->workbasedir);
	dput(ofs->workbasedir);
	if (ofs->upperdir_locked)
		ovl_inuse_unlock(ofs->upper_mnt->mnt_root);
	mntput(ofs->upper_mnt);
	for (i = 0; i < ofs->numlower; i++) {
		iput(ofs->lower_layers[i].trap);
		mntput(ofs->lower_layers[i].mnt);
	}
	for (i = 0; i < ofs->numlowerfs; i++)
		free_anon_bdev(ofs->lower_fs[i].pseudo_dev);
	kfree(ofs->lower_layers);
	kfree(ofs->lower_fs);

	kfree(ofs->config.lowerdir);
	kfree(ofs->config.upperdir);
	kfree(ofs->config.workdir);
	kfree(ofs->config.redirect_mode);
	if (ofs->creator_cred)
		put_cred(ofs->creator_cred);
	kfree(ofs);
}

static void ovl_put_super(struct super_block *sb)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	ovl_free_fs(ofs);
}

/* Sync real dirty inodes in upper filesystem (if it exists) */
static int ovl_sync_fs(struct super_block *sb, int wait)
{
	struct ovl_fs *ofs = sb->s_fs_info;
	struct super_block *upper_sb;
	int ret;

	if (!ofs->upper_mnt)
		return 0;

	/*
	 * If this is a sync(2) call or an emergency sync, all the super blocks
	 * will be iterated, including upper_sb, so no need to do anything.
	 *
	 * If this is a syncfs(2) call, then we do need to call
	 * sync_filesystem() on upper_sb, but enough if we do it when being
	 * called with wait == 1.
	 */
	if (!wait)
		return 0;

	upper_sb = ofs->upper_mnt->mnt_sb;

	down_read(&upper_sb->s_umount);
	ret = sync_filesystem(upper_sb);
	up_read(&upper_sb->s_umount);

	return ret;
}

/**
 * ovl_statfs
 * @sb: The overlayfs super block
 * @buf: The struct kstatfs to fill in with stats
 *
 * Get the filesystem statistics.  As writes always target the upper layer
 * filesystem pass the statfs to the upper filesystem (if it exists)
 */
static int ovl_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct ovl_fs *ofs = dentry->d_sb->s_fs_info;
	struct dentry *root_dentry = dentry->d_sb->s_root;
	struct path path;
	int err;

	ovl_path_real(root_dentry, &path);

	err = vfs_statfs(&path, buf);
	if (!err) {
		buf->f_namelen = ofs->namelen;
		buf->f_type = OVERLAYFS_SUPER_MAGIC;
	}

	return err;
}

/* Will this overlay be forced to mount/remount ro? */
static bool ovl_force_readonly(struct ovl_fs *ofs)
{
	return (!ofs->upper_mnt || !ofs->workdir);
}

static const char *ovl_redirect_mode_def(void)
{
	return ovl_redirect_dir_def ? "on" : "off";
}

enum {
	OVL_XINO_OFF,
	OVL_XINO_AUTO,
	OVL_XINO_ON,
};

static const char * const ovl_xino_str[] = {
	"off",
	"auto",
	"on",
};

static inline int ovl_xino_def(void)
{
	return ovl_xino_auto_def ? OVL_XINO_AUTO : OVL_XINO_OFF;
}

/**
 * ovl_show_options
 *
 * Prints the mount options for a given superblock.
 * Returns zero; does not fail.
 */
static int ovl_show_options(struct seq_file *m, struct dentry *dentry)
{
	struct super_block *sb = dentry->d_sb;
	struct ovl_fs *ofs = sb->s_fs_info;

	seq_show_option(m, "lowerdir", ofs->config.lowerdir);
	if (ofs->config.upperdir) {
		seq_show_option(m, "upperdir", ofs->config.upperdir);
		seq_show_option(m, "workdir", ofs->config.workdir);
	}
	if (ofs->config.default_permissions)
		seq_puts(m, ",default_permissions");
	if (strcmp(ofs->config.redirect_mode, ovl_redirect_mode_def()) != 0)
		seq_printf(m, ",redirect_dir=%s", ofs->config.redirect_mode);
	if (ofs->config.index != ovl_index_def)
		seq_printf(m, ",index=%s", ofs->config.index ? "on" : "off");
	if (ofs->config.nfs_export != ovl_nfs_export_def)
		seq_printf(m, ",nfs_export=%s", ofs->config.nfs_export ?
						"on" : "off");
	if (ofs->config.xino != ovl_xino_def())
		seq_printf(m, ",xino=%s", ovl_xino_str[ofs->config.xino]);
	if (ofs->config.metacopy != ovl_metacopy_def)
		seq_printf(m, ",metacopy=%s",
			   ofs->config.metacopy ? "on" : "off");
	return 0;
}

static int ovl_remount(struct super_block *sb, int *flags, char *data)
{
	struct ovl_fs *ofs = sb->s_fs_info;

	if (!(*flags & SB_RDONLY) && ovl_force_readonly(ofs))
		return -EROFS;

	return 0;
}

static const struct super_operations ovl_super_operations = {
	.alloc_inode	= ovl_alloc_inode,
	.free_inode	= ovl_free_inode,
	.destroy_inode	= ovl_destroy_inode,
	.drop_inode	= generic_delete_inode,
	.put_super	= ovl_put_super,
	.sync_fs	= ovl_sync_fs,
	.statfs		= ovl_statfs,
	.show_options	= ovl_show_options,
	.remount_fs	= ovl_remount,
};

enum {
	OPT_LOWERDIR,
	OPT_UPPERDIR,
	OPT_WORKDIR,
	OPT_DEFAULT_PERMISSIONS,
	OPT_REDIRECT_DIR,
	OPT_INDEX_ON,
	OPT_INDEX_OFF,
	OPT_NFS_EXPORT_ON,
	OPT_NFS_EXPORT_OFF,
	OPT_XINO_ON,
	OPT_XINO_OFF,
	OPT_XINO_AUTO,
	OPT_METACOPY_ON,
	OPT_METACOPY_OFF,
	OPT_ERR,
};

static const match_table_t ovl_tokens = {
	{OPT_LOWERDIR,			"lowerdir=%s"},
	{OPT_UPPERDIR,			"upperdir=%s"},
	{OPT_WORKDIR,			"workdir=%s"},
	{OPT_DEFAULT_PERMISSIONS,	"default_permissions"},
	{OPT_REDIRECT_DIR,		"redirect_dir=%s"},
	{OPT_INDEX_ON,			"index=on"},
	{OPT_INDEX_OFF,			"index=off"},
	{OPT_NFS_EXPORT_ON,		"nfs_export=on"},
	{OPT_NFS_EXPORT_OFF,		"nfs_export=off"},
	{OPT_XINO_ON,			"xino=on"},
	{OPT_XINO_OFF,			"xino=off"},
	{OPT_XINO_AUTO,			"xino=auto"},
	{OPT_METACOPY_ON,		"metacopy=on"},
	{OPT_METACOPY_OFF,		"metacopy=off"},
	{OPT_ERR,			NULL}
};

static char *ovl_next_opt(char **s)
{
	char *sbegin = *s;
	char *p;

	if (sbegin == NULL)
		return NULL;

	for (p = sbegin; *p; p++) {
		if (*p == '\\') {
			p++;
			if (!*p)
				break;
		} else if (*p == ',') {
			*p = '\0';
			*s = p + 1;
			return sbegin;
		}
	}
	*s = NULL;
	return sbegin;
}

static int ovl_parse_redirect_mode(struct ovl_config *config, const char *mode)
{
	if (strcmp(mode, "on") == 0) {
		config->redirect_dir = true;
		/*
		 * Does not make sense to have redirect creation without
		 * redirect following.
		 */
		config->redirect_follow = true;
	} else if (strcmp(mode, "follow") == 0) {
		config->redirect_follow = true;
	} else if (strcmp(mode, "off") == 0) {
		if (ovl_redirect_always_follow)
			config->redirect_follow = true;
	} else if (strcmp(mode, "nofollow") != 0) {
		pr_err("overlayfs: bad mount option \"redirect_dir=%s\"\n",
		       mode);
		return -EINVAL;
	}

	return 0;
}

static int ovl_parse_opt(char *opt, struct ovl_config *config)
{
	char *p;
	int err;
	bool metacopy_opt = false, redirect_opt = false;

	config->redirect_mode = kstrdup(ovl_redirect_mode_def(), GFP_KERNEL);
	if (!config->redirect_mode)
		return -ENOMEM;

	while ((p = ovl_next_opt(&opt)) != NULL) {
		int token;
		substring_t args[MAX_OPT_ARGS];

		if (!*p)
			continue;

		token = match_token(p, ovl_tokens, args);
		switch (token) {
		case OPT_UPPERDIR:
			kfree(config->upperdir);
			config->upperdir = match_strdup(&args[0]);
			if (!config->upperdir)
				return -ENOMEM;
			break;

		case OPT_LOWERDIR:
			kfree(config->lowerdir);
			config->lowerdir = match_strdup(&args[0]);
			if (!config->lowerdir)
				return -ENOMEM;
			break;

		case OPT_WORKDIR:
			kfree(config->workdir);
			config->workdir = match_strdup(&args[0]);
			if (!config->workdir)
				return -ENOMEM;
			break;

		case OPT_DEFAULT_PERMISSIONS:
			config->default_permissions = true;
			break;

		case OPT_REDIRECT_DIR:
			kfree(config->redirect_mode);
			config->redirect_mode = match_strdup(&args[0]);
			if (!config->redirect_mode)
				return -ENOMEM;
			redirect_opt = true;
			break;

		case OPT_INDEX_ON:
			config->index = true;
			break;

		case OPT_INDEX_OFF:
			config->index = false;
			break;

		case OPT_NFS_EXPORT_ON:
			config->nfs_export = true;
			break;

		case OPT_NFS_EXPORT_OFF:
			config->nfs_export = false;
			break;

		case OPT_XINO_ON:
			config->xino = OVL_XINO_ON;
			break;

		case OPT_XINO_OFF:
			config->xino = OVL_XINO_OFF;
			break;

		case OPT_XINO_AUTO:
			config->xino = OVL_XINO_AUTO;
			break;

		case OPT_METACOPY_ON:
			config->metacopy = true;
			metacopy_opt = true;
			break;

		case OPT_METACOPY_OFF:
			config->metacopy = false;
			break;

		default:
			pr_err("overlayfs: unrecognized mount option \"%s\" or missing value\n", p);
			return -EINVAL;
		}
	}

	/* Workdir is useless in non-upper mount */
	if (!config->upperdir && config->workdir) {
		pr_info("overlayfs: option \"workdir=%s\" is useless in a non-upper mount, ignore\n",
			config->workdir);
		kfree(config->workdir);
		config->workdir = NULL;
	}

	err = ovl_parse_redirect_mode(config, config->redirect_mode);
	if (err)
		return err;

	/*
	 * This is to make the logic below simpler.  It doesn't make any other
	 * difference, since config->redirect_dir is only used for upper.
	 */
	if (!config->upperdir && config->redirect_follow)
		config->redirect_dir = true;

	/* Resolve metacopy -> redirect_dir dependency */
	if (config->metacopy && !config->redirect_dir) {
		if (metacopy_opt && redirect_opt) {
			pr_err("overlayfs: conflicting options: metacopy=on,redirect_dir=%s\n",
			       config->redirect_mode);
			return -EINVAL;
		}
		if (redirect_opt) {
			/*
			 * There was an explicit redirect_dir=... that resulted
			 * in this conflict.
			 */
			pr_info("overlayfs: disabling metacopy due to redirect_dir=%s\n",
				config->redirect_mode);
			config->metacopy = false;
		} else {
			/* Automatically enable redirect otherwise. */
			config->redirect_follow = config->redirect_dir = true;
		}
	}

	return 0;
}

#define OVL_WORKDIR_NAME "work"
#define OVL_INDEXDIR_NAME "index"

static struct dentry *ovl_workdir_create(struct ovl_fs *ofs,
					 const char *name, bool persist)
{
	struct inode *dir =  ofs->workbasedir->d_inode;
	struct vfsmount *mnt = ofs->upper_mnt;
	struct dentry *work;
	int err;
	bool retried = false;
	bool locked = false;

	inode_lock_nested(dir, I_MUTEX_PARENT);
	locked = true;

retry:
	work = lookup_one_len(name, ofs->workbasedir, strlen(name));

	if (!IS_ERR(work)) {
		struct iattr attr = {
			.ia_valid = ATTR_MODE,
			.ia_mode = S_IFDIR | 0,
		};

		if (work->d_inode) {
			err = -EEXIST;
			if (retried)
				goto out_dput;

			if (persist)
				goto out_unlock;

			retried = true;
			ovl_workdir_cleanup(dir, mnt, work, 0);
			dput(work);
			goto retry;
		}

		work = ovl_create_real(dir, work, OVL_CATTR(attr.ia_mode));
		err = PTR_ERR(work);
		if (IS_ERR(work))
			goto out_err;

		/*
		 * Try to remove POSIX ACL xattrs from workdir.  We are good if:
		 *
		 * a) success (there was a POSIX ACL xattr and was removed)
		 * b) -ENODATA (there was no POSIX ACL xattr)
		 * c) -EOPNOTSUPP (POSIX ACL xattrs are not supported)
		 *
		 * There are various other error values that could effectively
		 * mean that the xattr doesn't exist (e.g. -ERANGE is returned
		 * if the xattr name is too long), but the set of filesystems
		 * allowed as upper are limited to "normal" ones, where checking
		 * for the above two errors is sufficient.
		 */
		err = vfs_removexattr(work, XATTR_NAME_POSIX_ACL_DEFAULT);
		if (err && err != -ENODATA && err != -EOPNOTSUPP)
			goto out_dput;

		err = vfs_removexattr(work, XATTR_NAME_POSIX_ACL_ACCESS);
		if (err && err != -ENODATA && err != -EOPNOTSUPP)
			goto out_dput;

		/* Clear any inherited mode bits */
		inode_lock(work->d_inode);
		err = notify_change(work, &attr, NULL);
		inode_unlock(work->d_inode);
		if (err)
			goto out_dput;
	} else {
		err = PTR_ERR(work);
		goto out_err;
	}
out_unlock:
	if (locked)
		inode_unlock(dir);

	return work;

out_dput:
	dput(work);
out_err:
	pr_warn("overlayfs: failed to create directory %s/%s (errno: %i); mounting read-only\n",
		ofs->config.workdir, name, -err);
	work = NULL;
	goto out_unlock;
}

static void ovl_unescape(char *s)
{
	char *d = s;

	for (;; s++, d++) {
		if (*s == '\\')
			s++;
		*d = *s;
		if (!*s)
			break;
	}
}

static int ovl_mount_dir_noesc(const char *name, struct path *path)
{
	int err = -EINVAL;

	if (!*name) {
		pr_err("overlayfs: empty lowerdir\n");
		goto out;
	}
	err = kern_path(name, LOOKUP_FOLLOW, path);
	if (err) {
		pr_err("overlayfs: failed to resolve '%s': %i\n", name, err);
		goto out;
	}
	err = -EINVAL;
	if (ovl_dentry_weird(path->dentry)) {
		pr_err("overlayfs: filesystem on '%s' not supported\n", name);
		goto out_put;
	}
	if (!d_is_dir(path->dentry)) {
		pr_err("overlayfs: '%s' not a directory\n", name);
		goto out_put;
	}
	return 0;

out_put:
	path_put_init(path);
out:
	return err;
}

static int ovl_mount_dir(const char *name, struct path *path)
{
	int err = -ENOMEM;
	char *tmp = kstrdup(name, GFP_KERNEL);

	if (tmp) {
		ovl_unescape(tmp);						// 过滤文件名中还有'\'的字符
		err = ovl_mount_dir_noesc(tmp, path);				// 根据路径名tmp找到对应装载目录的path

		if (!err)
			if (ovl_dentry_remote(path->dentry)) {
				pr_err("overlayfs: filesystem on '%s' not supported as upperdir\n",
				       tmp);
				path_put_init(path);
				err = -EINVAL;
			}
		kfree(tmp);
	}
	return err;
}

static int ovl_check_namelen(struct path *path, struct ovl_fs *ofs,
			     const char *name)
{
	struct kstatfs statfs;
	int err = vfs_statfs(path, &statfs);

	if (err)
		pr_err("overlayfs: statfs failed on '%s'\n", name);
	else
		ofs->namelen = max(ofs->namelen, statfs.f_namelen);

	return err;
}

static int ovl_lower_dir(const char *name, struct path *path,
			 struct ovl_fs *ofs, int *stack_depth, bool *remote)	// 路径查找，根据name找到具体文件系统的目录对应的path
{
	int fh_type;
	int err;

	err = ovl_mount_dir_noesc(name, path);					// 根据路径名name找到对应目录并放置在path
	if (err)
		goto out;

	err = ovl_check_namelen(path, ofs, name);				// 设置ofs->namelen为path对应文件名长度和ofs->namelen的最大值
	if (err)
		goto out_put;

	*stack_depth = max(*stack_depth, path->mnt->mnt_sb->s_stack_depth);	// 设置sb->s_stack_depth为sb->s_stack_depth和当前lower层path对应vfsmount->mnt_sb->s_stack_depth的最大值

	if (ovl_dentry_remote(path->dentry))
		*remote = true;

	/*
	 * The inodes index feature and NFS export need to encode and decode
	 * file handles, so they require that all layers support them.
	 */
	fh_type = ovl_can_decode_fh(path->dentry->d_sb);
	if ((ofs->config.nfs_export ||
	     (ofs->config.index && ofs->config.upperdir)) && !fh_type) {
		ofs->config.index = false;
		ofs->config.nfs_export = false;
		pr_warn("overlayfs: fs on '%s' does not support file handles, falling back to index=off,nfs_export=off.\n",
			name);
	}

	/* Check if lower fs has 32bit inode numbers */
	if (fh_type != FILEID_INO32_GEN)
		ofs->xino_bits = 0;

	return 0;

out_put:
	path_put_init(path);
out:
	return err;
}

/* Workdir should not be subdir of upperdir and vice versa */
static bool ovl_workdir_ok(struct dentry *workdir, struct dentry *upperdir)
{
	bool ok = false;

	if (workdir != upperdir) {
		ok = (lock_rename(workdir, upperdir) == NULL);
		unlock_rename(workdir, upperdir);
	}
	return ok;
}

static unsigned int ovl_split_lowerdirs(char *str)
{
	unsigned int ctr = 1;
	char *s, *d;

	for (s = d = str;; s++, d++) {
		if (*s == '\\') {
			s++;
		} else if (*s == ':') {
			*d = '\0';
			ctr++;
			continue;
		}
		*d = *s;
		if (!*s)
			break;
	}
	return ctr;
}

static int __maybe_unused
ovl_posix_acl_xattr_get(const struct xattr_handler *handler,
			struct dentry *dentry, struct inode *inode,
			const char *name, void *buffer, size_t size)
{
	return ovl_xattr_get(dentry, inode, handler->name, buffer, size);
}

static int __maybe_unused
ovl_posix_acl_xattr_set(const struct xattr_handler *handler,
			struct dentry *dentry, struct inode *inode,
			const char *name, const void *value,
			size_t size, int flags)
{
	struct dentry *workdir = ovl_workdir(dentry);
	struct inode *realinode = ovl_inode_real(inode);
	struct posix_acl *acl = NULL;
	int err;

	/* Check that everything is OK before copy-up */
	if (value) {
		acl = posix_acl_from_xattr(&init_user_ns, value, size);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
	}
	err = -EOPNOTSUPP;
	if (!IS_POSIXACL(d_inode(workdir)))
		goto out_acl_release;
	if (!realinode->i_op->set_acl)
		goto out_acl_release;
	if (handler->flags == ACL_TYPE_DEFAULT && !S_ISDIR(inode->i_mode)) {
		err = acl ? -EACCES : 0;
		goto out_acl_release;
	}
	err = -EPERM;
	if (!inode_owner_or_capable(inode))
		goto out_acl_release;

	posix_acl_release(acl);

	/*
	 * Check if sgid bit needs to be cleared (actual setacl operation will
	 * be done with mounter's capabilities and so that won't do it for us).
	 */
	if (unlikely(inode->i_mode & S_ISGID) &&
	    handler->flags == ACL_TYPE_ACCESS &&
	    !in_group_p(inode->i_gid) &&
	    !capable_wrt_inode_uidgid(inode, CAP_FSETID)) {
		struct iattr iattr = { .ia_valid = ATTR_KILL_SGID };

		err = ovl_setattr(dentry, &iattr);
		if (err)
			return err;
	}

	err = ovl_xattr_set(dentry, inode, handler->name, value, size, flags);
	if (!err)
		ovl_copyattr(ovl_inode_real(inode), inode);

	return err;

out_acl_release:
	posix_acl_release(acl);
	return err;
}

static int ovl_own_xattr_get(const struct xattr_handler *handler,
			     struct dentry *dentry, struct inode *inode,
			     const char *name, void *buffer, size_t size)
{
	return -EOPNOTSUPP;
}

static int ovl_own_xattr_set(const struct xattr_handler *handler,
			     struct dentry *dentry, struct inode *inode,
			     const char *name, const void *value,
			     size_t size, int flags)
{
	return -EOPNOTSUPP;
}

static int ovl_other_xattr_get(const struct xattr_handler *handler,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, void *buffer, size_t size)
{
	return ovl_xattr_get(dentry, inode, name, buffer, size);
}

static int ovl_other_xattr_set(const struct xattr_handler *handler,
			       struct dentry *dentry, struct inode *inode,
			       const char *name, const void *value,
			       size_t size, int flags)
{
	return ovl_xattr_set(dentry, inode, name, value, size, flags);
}

static const struct xattr_handler __maybe_unused
ovl_posix_acl_access_xattr_handler = {
	.name = XATTR_NAME_POSIX_ACL_ACCESS,
	.flags = ACL_TYPE_ACCESS,
	.get = ovl_posix_acl_xattr_get,
	.set = ovl_posix_acl_xattr_set,
};

static const struct xattr_handler __maybe_unused
ovl_posix_acl_default_xattr_handler = {
	.name = XATTR_NAME_POSIX_ACL_DEFAULT,
	.flags = ACL_TYPE_DEFAULT,
	.get = ovl_posix_acl_xattr_get,
	.set = ovl_posix_acl_xattr_set,
};

static const struct xattr_handler ovl_own_xattr_handler = {
	.prefix	= OVL_XATTR_PREFIX,
	.get = ovl_own_xattr_get,
	.set = ovl_own_xattr_set,
};

static const struct xattr_handler ovl_other_xattr_handler = {
	.prefix	= "", /* catch all */
	.get = ovl_other_xattr_get,
	.set = ovl_other_xattr_set,
};

static const struct xattr_handler *ovl_xattr_handlers[] = {
#ifdef CONFIG_FS_POSIX_ACL
	&ovl_posix_acl_access_xattr_handler,
	&ovl_posix_acl_default_xattr_handler,
#endif
	&ovl_own_xattr_handler,
	&ovl_other_xattr_handler,
	NULL
};

static int ovl_setup_trap(struct super_block *sb, struct dentry *dir,
			  struct inode **ptrap, const char *name)		// 检查哈希表是否存在置上“trap”标记的inode和dir对应的inode相同，如果有则证明overlay层之间发生重叠返回错误，如果没有为dir的inode则打上“trap”标记并放入哈希表
{
	struct inode *trap;
	int err;

	trap = ovl_get_trap_inode(sb, dir);					// 检查哈希表是否存在置上“trap”标记的inode和dir对应的inode相同，如果有则证明overlay层之间发生重叠返回错误，如果没有为dir的inode则打上“trap”标记并放入哈希表，返回打上“trap”标记的inode
	err = PTR_ERR_OR_ZERO(trap);
	if (err) {
		if (err == -ELOOP)
			pr_err("overlayfs: conflicting %s path\n", name);
		return err;
	}

	*ptrap = trap;
	return 0;
}

/*
 * Determine how we treat concurrent use of upperdir/workdir based on the
 * index feature. This is papering over mount leaks of container runtimes,
 * for example, an old overlay mount is leaked and now its upperdir is
 * attempted to be used as a lower layer in a new overlay mount.
 */
static int ovl_report_in_use(struct ovl_fs *ofs, const char *name)
{
	if (ofs->config.index) {
		pr_err("overlayfs: %s is in-use as upperdir/workdir of another mount, mount with '-o index=off' to override exclusive upperdir protection.\n",
		       name);
		return -EBUSY;
	} else {
		pr_warn("overlayfs: %s is in-use as upperdir/workdir of another mount, accessing files from both mounts will result in undefined behavior.\n",
			name);
		return 0;
	}
}

static int ovl_get_upper(struct super_block *sb, struct ovl_fs *ofs,
			 struct path *upperpath)
{
	struct vfsmount *upper_mnt;
	int err;

	err = ovl_mount_dir(ofs->config.upperdir, upperpath);			// 根据路径名ofs->config.upperdir找到对应文件并放置在upperpath
	if (err)
		goto out;

	/* Upper fs should not be r/o */
	if (sb_rdonly(upperpath->mnt->mnt_sb)) {				// upper层文件必须是读写
		pr_err("overlayfs: upper fs is r/o, try multi-lower layers mount\n");
		err = -EINVAL;
		goto out;
	}

	err = ovl_check_namelen(upperpath, ofs, ofs->config.upperdir);		// 设置ofs->namelen为upperpath对应文件名长度和ofs->namelen的最大值
	if (err)
		goto out;

	err = ovl_setup_trap(sb, upperpath->dentry, &ofs->upperdir_trap,
			     "upperdir");					// 检查哈希表是否已有置上“trap”标记的ofs->upperdir_trap对应inode，如果没有则打上“trap”标记并放入哈希表
	if (err)
		goto out;

	upper_mnt = clone_private_mount(upperpath);				// 克隆upper层vfsmount对应的mount实例，返回vfsmount数据项
	err = PTR_ERR(upper_mnt);
	if (IS_ERR(upper_mnt)) {
		pr_err("overlayfs: failed to clone upperpath\n");
		goto out;
	}

	/* Don't inherit atime flags */
	upper_mnt->mnt_flags &= ~(MNT_NOATIME | MNT_NODIRATIME | MNT_RELATIME);
	ofs->upper_mnt = upper_mnt;						// 初始化overlay文件系统实例的upper_mnt

	if (ovl_inuse_trylock(ofs->upper_mnt->mnt_root)) {			// 检查upper层root inode是否有“I_OVL_INUSE”标记，如果没有则打上“I_OVL_INUSE”标记，如果有则说明upper层的目录被其他overlay文件系统使用，再次重用会给出警告
		ofs->upperdir_locked = true;
	} else {
		err = ovl_report_in_use(ofs, "upperdir");
		if (err)
			goto out;
	}

	err = 0;
out:
	return err;
}

static int ovl_make_workdir(struct super_block *sb, struct ovl_fs *ofs,
			    struct path *workpath)
{
	struct vfsmount *mnt = ofs->upper_mnt;
	struct dentry *temp;
	int fh_type;
	int err;

	err = mnt_want_write(mnt);
	if (err)
		return err;

	ofs->workdir = ovl_workdir_create(ofs, OVL_WORKDIR_NAME, false);	// 在ofs->workbasedir下创建work作为实际的工作目录，所以我们会看到$WORKDIR/work（$WORKDIR为overlaymount选项中的-o workdir=$WORKDIR）
	if (!ofs->workdir)
		goto out;

	err = ovl_setup_trap(sb, ofs->workdir, &ofs->workdir_trap, "workdir");	// 检查哈希表是否已有置上“trap”标记的ofs->workdir对应inode，如果没有则打上“trap”标记并放入哈希表，ofs->workdir是实际的工作目录，对应用户指定的workdir下的“work”目录
	if (err)
		goto out;

	/*
	 * Upper should support d_type, else whiteouts are visible.  Given
	 * workdir and upper are on same fs, we can do iterate_dir() on
	 * workdir. This check requires successful creation of workdir in
	 * previous step.
	 */
	err = ovl_check_d_type_supported(workpath);
	if (err < 0)
		goto out;

	/*
	 * We allowed this configuration and don't want to break users over
	 * kernel upgrade. So warn instead of erroring out.
	 */
	if (!err)
		pr_warn("overlayfs: upper fs needs to support d_type.\n");

	/* Check if upper/work fs supports O_TMPFILE */
	temp = ovl_do_tmpfile(ofs->workdir, S_IFREG | 0);
	ofs->tmpfile = !IS_ERR(temp);
	if (ofs->tmpfile)
		dput(temp);
	else
		pr_warn("overlayfs: upper fs does not support tmpfile.\n");

	/*
	 * Check if upper/work fs supports trusted.overlay.* xattr
	 */
	err = ovl_do_setxattr(ofs->workdir, OVL_XATTR_OPAQUE, "0", 1, 0);
	if (err) {
		ofs->noxattr = true;
		ofs->config.index = false;
		ofs->config.metacopy = false;
		pr_warn("overlayfs: upper fs does not support xattr, falling back to index=off and metacopy=off.\n");
		err = 0;
	} else {
		vfs_removexattr(ofs->workdir, OVL_XATTR_OPAQUE);
	}

	/* Check if upper/work fs supports file handles */
	fh_type = ovl_can_decode_fh(ofs->workdir->d_sb);
	if (ofs->config.index && !fh_type) {
		ofs->config.index = false;
		pr_warn("overlayfs: upper fs does not support file handles, falling back to index=off.\n");
	}

	/* Check if upper fs has 32bit inode numbers */
	if (fh_type != FILEID_INO32_GEN)
		ofs->xino_bits = 0;

	/* NFS export of r/w mount depends on index */
	if (ofs->config.nfs_export && !ofs->config.index) {
		pr_warn("overlayfs: NFS export requires \"index=on\", falling back to nfs_export=off.\n");
		ofs->config.nfs_export = false;
	}
out:
	mnt_drop_write(mnt);
	return err;
}

static int ovl_get_workdir(struct super_block *sb, struct ovl_fs *ofs,
			   struct path *upperpath)
{
	int err;
	struct path workpath = { };

	err = ovl_mount_dir(ofs->config.workdir, &workpath);			// 根据路径名ofs->config.workdir找到对应文件并放置在workpath
	if (err)
		goto out;

	err = -EINVAL;
	if (upperpath->mnt != workpath.mnt) {					// overlay要求workdir和upperdir必须在同一个装载实例下
		pr_err("overlayfs: workdir and upperdir must reside under the same mount\n");
		goto out;
	}
	if (!ovl_workdir_ok(workpath.dentry, upperpath->dentry)) {		// workdir和upperdir不能是同一个，也不能互为祖先目录（包括父子、孙子等）
		pr_err("overlayfs: workdir and upperdir must be separate subtrees\n");
		goto out;
	}

	ofs->workbasedir = dget(workpath.dentry);

	if (ovl_inuse_trylock(ofs->workbasedir)) {				// 检查workdir的inode是否有“I_OVL_INUSE”标记，如果没有则打上“I_OVL_INUSE”标记，如果有则说明workdir被其他overlay文件系统当做upper层或wordir使用，再次重用会给出警告
		ofs->workdir_locked = true;
	} else {
		err = ovl_report_in_use(ofs, "workdir");
		if (err)
			goto out;
	}

	err = ovl_setup_trap(sb, ofs->workbasedir, &ofs->workbasedir_trap,
			     "workdir");					// 检查哈希表是否已有置上“trap”标记的ofs->workbasedir对应inode，如果没有则打上“trap”标记并放入哈希表
	if (err)
		goto out;

	err = ovl_make_workdir(sb, ofs, &workpath);				// 在ofs->workbasedir创建实际工作目录

out:
	path_put(&workpath);

	return err;
}

static int ovl_get_indexdir(struct super_block *sb, struct ovl_fs *ofs,
			    struct ovl_entry *oe, struct path *upperpath)
{
	struct vfsmount *mnt = ofs->upper_mnt;
	int err;

	err = mnt_want_write(mnt);
	if (err)
		return err;

	/* Verify lower root is upper root origin */
	err = ovl_verify_origin(upperpath->dentry, oe->lowerstack[0].dentry,
				true);
	if (err) {
		pr_err("overlayfs: failed to verify upper root origin\n");
		goto out;
	}

	ofs->indexdir = ovl_workdir_create(ofs, OVL_INDEXDIR_NAME, true);
	if (ofs->indexdir) {
		err = ovl_setup_trap(sb, ofs->indexdir, &ofs->indexdir_trap,
				     "indexdir");
		if (err)
			goto out;

		/*
		 * Verify upper root is exclusively associated with index dir.
		 * Older kernels stored upper fh in "trusted.overlay.origin"
		 * xattr. If that xattr exists, verify that it is a match to
		 * upper dir file handle. In any case, verify or set xattr
		 * "trusted.overlay.upper" to indicate that index may have
		 * directory entries.
		 */
		if (ovl_check_origin_xattr(ofs->indexdir)) {
			err = ovl_verify_set_fh(ofs->indexdir, OVL_XATTR_ORIGIN,
						upperpath->dentry, true, false);
			if (err)
				pr_err("overlayfs: failed to verify index dir 'origin' xattr\n");
		}
		err = ovl_verify_upper(ofs->indexdir, upperpath->dentry, true);
		if (err)
			pr_err("overlayfs: failed to verify index dir 'upper' xattr\n");

		/* Cleanup bad/stale/orphan index entries */
		if (!err)
			err = ovl_indexdir_cleanup(ofs);
	}
	if (err || !ofs->indexdir)
		pr_warn("overlayfs: try deleting index dir or mounting with '-o index=off' to disable inodes index.\n");

out:
	mnt_drop_write(mnt);
	return err;
}

static bool ovl_lower_uuid_ok(struct ovl_fs *ofs, const uuid_t *uuid)
{
	unsigned int i;

	if (!ofs->config.nfs_export && !(ofs->config.index && ofs->upper_mnt))
		return true;

	for (i = 0; i < ofs->numlowerfs; i++) {
		/*
		 * We use uuid to associate an overlay lower file handle with a
		 * lower layer, so we can accept lower fs with null uuid as long
		 * as all lower layers with null uuid are on the same fs.
		 */
		if (uuid_equal(&ofs->lower_fs[i].sb->s_uuid, uuid))
			return false;
	}
	return true;
}

/* Get a unique fsid for the layer */
static int ovl_get_fsid(struct ovl_fs *ofs, const struct path *path)
{
	struct super_block *sb = path->mnt->mnt_sb;
	unsigned int i;
	dev_t dev;
	int err;

	/* fsid 0 is reserved for upper fs even with non upper overlay */
	if (ofs->upper_mnt && ofs->upper_mnt->mnt_sb == sb)
		return 0;

	for (i = 0; i < ofs->numlowerfs; i++) {
		if (ofs->lower_fs[i].sb == sb)
			return i + 1;
	}

	if (!ovl_lower_uuid_ok(ofs, &sb->s_uuid)) {
		ofs->config.index = false;
		ofs->config.nfs_export = false;
		pr_warn("overlayfs: %s uuid detected in lower fs '%pd2', falling back to index=off,nfs_export=off.\n",
			uuid_is_null(&sb->s_uuid) ? "null" : "conflicting",
			path->dentry);
	}

	err = get_anon_bdev(&dev);
	if (err) {
		pr_err("overlayfs: failed to get anonymous bdev for lowerpath\n");
		return err;
	}

	ofs->lower_fs[ofs->numlowerfs].sb = sb;
	ofs->lower_fs[ofs->numlowerfs].pseudo_dev = dev;
	ofs->numlowerfs++;

	return ofs->numlowerfs;
}

static int ovl_get_lower_layers(struct super_block *sb, struct ovl_fs *ofs,
				struct path *stack, unsigned int numlower)	// 将overlay的所有lower层信息填充到ovl private超级块ofs->lower_layers和ofs->lower_fs
{
	int err;
	unsigned int i;

	err = -ENOMEM;
	ofs->lower_layers = kcalloc(numlower, sizeof(struct ovl_layer),
				    GFP_KERNEL);
	if (ofs->lower_layers == NULL)
		goto out;

	ofs->lower_fs = kcalloc(numlower, sizeof(struct ovl_sb),
				GFP_KERNEL);
	if (ofs->lower_fs == NULL)
		goto out;

	for (i = 0; i < numlower; i++) {
		struct vfsmount *mnt;
		struct inode *trap;
		int fsid;

		err = fsid = ovl_get_fsid(ofs, &stack[i]);
		if (err < 0)
			goto out;

		err = ovl_setup_trap(sb, stack[i].dentry, &trap, "lowerdir");	// 检查哈希表是否已有置上“trap”标记的stack[i].dentry对应inode，如果没有则打上“trap”标记并放入哈希表
		if (err)
			goto out;

		if (ovl_is_inuse(stack[i].dentry)) {				// 检查lower层root inode是否有“I_OVL_INUSE”标记，如果有则说明lower层的目录被其他overlay文件系统当做upper层或wordir使用，再次重用会给出警告
			err = ovl_report_in_use(ofs, "lowerdir");
			if (err)
				goto out;
		}

		mnt = clone_private_mount(&stack[i]);				// 克隆第i个lower层装载实例
		err = PTR_ERR(mnt);
		if (IS_ERR(mnt)) {
			pr_err("overlayfs: failed to clone lowerpath\n");
			iput(trap);
			goto out;
		}

		/*
		 * Make lower layers R/O.  That way fchmod/fchown on lower file
		 * will fail instead of modifying lower fs.
		 */
		mnt->mnt_flags |= MNT_READONLY | MNT_NOATIME;			// lower层文件系统是只读

		ofs->lower_layers[ofs->numlower].trap = trap;			// 记录lower层的trap inode
		ofs->lower_layers[ofs->numlower].mnt = mnt;			// ovl private超级块在lower层的装载实例是clone的
		ofs->lower_layers[ofs->numlower].idx = i + 1;
		ofs->lower_layers[ofs->numlower].fsid = fsid;
		if (fsid) {
			ofs->lower_layers[ofs->numlower].fs =
				&ofs->lower_fs[fsid - 1];
		}
		ofs->numlower++;
	}

	/*
	 * When all layers on same fs, overlay can use real inode numbers.
	 * With mount option "xino=on", mounter declares that there are enough
	 * free high bits in underlying fs to hold the unique fsid.
	 * If overlayfs does encounter underlying inodes using the high xino
	 * bits reserved for fsid, it emits a warning and uses the original
	 * inode number.
	 */
	if (!ofs->numlowerfs || (ofs->numlowerfs == 1 && !ofs->upper_mnt)) {
		ofs->xino_bits = 0;
		ofs->config.xino = OVL_XINO_OFF;
	} else if (ofs->config.xino == OVL_XINO_ON && !ofs->xino_bits) {
		/*
		 * This is a roundup of number of bits needed for numlowerfs+1
		 * (i.e. ilog2(numlowerfs+1 - 1) + 1). fsid 0 is reserved for
		 * upper fs even with non upper overlay.
		 */
		BUILD_BUG_ON(ilog2(OVL_MAX_STACK) > 31);
		ofs->xino_bits = ilog2(ofs->numlowerfs) + 1;
	}

	if (ofs->xino_bits) {
		pr_info("overlayfs: \"xino\" feature enabled using %d upper inode bits.\n",
			ofs->xino_bits);
	}

	err = 0;
out:
	return err;
}

static struct ovl_entry *ovl_get_lowerstack(struct super_block *sb,
					    struct ovl_fs *ofs)
{
	int err;
	char *lowertmp, *lower;
	struct path *stack = NULL;						// 存放每个lower层的vfsmount和dentry
	unsigned int stacklen, numlower = 0, i;
	bool remote = false;
	struct ovl_entry *oe;

	err = -ENOMEM;
	lowertmp = kstrdup(ofs->config.lowerdir, GFP_KERNEL);
	if (!lowertmp)
		goto out_err;

	err = -EINVAL;
	stacklen = ovl_split_lowerdirs(lowertmp);				// lower层路径名以':'分割，过滤含有'\'的字符，新的lower层路径以'\0'分割
	if (stacklen > OVL_MAX_STACK) {						// overlay最多支持500个lower层
		pr_err("overlayfs: too many lower directories, limit is %d\n",
		       OVL_MAX_STACK);
		goto out_err;
	} else if (!ofs->config.upperdir && stacklen == 1) {			// 在upper层不存在的情况下，overlay至少应该有2个lower层，不然没有重复挂载的必要
		pr_err("overlayfs: at least 2 lowerdir are needed while upperdir nonexistent\n");
		goto out_err;
	} else if (!ofs->config.upperdir && ofs->config.nfs_export &&
		   ofs->config.redirect_follow) {
		pr_warn("overlayfs: NFS export requires \"redirect_dir=nofollow\" on non-upper mount, falling back to nfs_export=off.\n");
		ofs->config.nfs_export = false;
	}

	err = -ENOMEM;
	stack = kcalloc(stacklen, sizeof(struct path), GFP_KERNEL);
	if (!stack)
		goto out_err;

	err = -EINVAL;
	lower = lowertmp;
	for (numlower = 0; numlower < stacklen; numlower++) {
		err = ovl_lower_dir(lower, &stack[numlower], ofs,
				    &sb->s_stack_depth, &remote);		// stack[numlower]是指定第numlower个lower层的路径(path)，调用具体文件系统接口查找名字lower对应的path
		if (err)
			goto out_err;

		lower = strchr(lower, '\0') + 1;				// 找到下一个lower层路径名
	}

	err = -EINVAL;
	sb->s_stack_depth++;							// 此时文件系统栈深度应该自增，因为overlay是基于其他文件系统的
	if (sb->s_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {			// 所以overlay下所有层的文件系统不能是overlay，因为在普通文件系统装载一次overlay之后sb->s_stack_depth=2
		pr_err("overlayfs: maximum fs stacking depth exceeded\n");
		goto out_err;
	}

	err = ovl_get_lower_layers(sb, ofs, stack, numlower);			// 将每个lower层的信息放置于ovl private超级块ofs->lower_layers
	if (err)
		goto out_err;

	err = -ENOMEM;
	oe = ovl_alloc_entry(numlower);						// 申请根目录的ovl_dentry
	if (!oe)
		goto out_err;

	for (i = 0; i < numlower; i++) {					// 初始化根目录的ovl_dentry->lowerstack
		oe->lowerstack[i].dentry = dget(stack[i].dentry);		// overlay根目录的ovl_dentry中每个lowerstack的dentry指向每个lower层文件的dentry
		oe->lowerstack[i].layer = &ofs->lower_layers[i];
	}

	if (remote)
		sb->s_d_op = &ovl_reval_dentry_operations;
	else
		sb->s_d_op = &ovl_dentry_operations;

out:
	for (i = 0; i < numlower; i++)
		path_put(&stack[i]);
	kfree(stack);
	kfree(lowertmp);

	return oe;

out_err:
	oe = ERR_PTR(err);
	goto out;
}

/*
 * Check if this layer root is a descendant of:
 * - another layer of this overlayfs instance
 * - upper/work dir of any overlayfs instance
 */
static int ovl_check_layer(struct super_block *sb, struct ovl_fs *ofs,
			   struct dentry *dentry, const char *name)
{
	struct dentry *next = dentry, *parent;
	int err = 0;

	if (!dentry)
		return 0;

	parent = dget_parent(next);

	/* Walk back ancestors to root (inclusive) looking for traps */
	while (!err && parent != next) {					// 递归遍历parent
		if (ovl_lookup_trap_inode(sb, parent)) {			// parent inode是否在哈希表中存在对应置上“trap”标记的inode，如果有则发生重叠
			err = -ELOOP;
			pr_err("overlayfs: overlapping %s path\n", name);
		} else if (ovl_is_inuse(parent)) {				// parent不能是别的overlay文件系统正在使用的upper层或workdir，如果是则警告
			err = ovl_report_in_use(ofs, name);
		}
		next = parent;
		parent = dget_parent(next);
		dput(next);
	}

	dput(parent);

	return err;
}

/*
 * Check if any of the layers or work dirs overlap.
 */
static int ovl_check_overlapping_layers(struct super_block *sb,
					struct ovl_fs *ofs)
{
	int i, err;

	if (ofs->upper_mnt) {
		err = ovl_check_layer(sb, ofs, ofs->upper_mnt->mnt_root,
				      "upperdir");				// 对于upper层，检查哈希表是否已有置上“trap”标记的ofs->upper_mnt->mnt_root对应inode；检查ofs->upper_mnt->mnt_root是否有“I_OVL_INUSE”标记
		if (err)
			return err;

		/*
		 * Checking workbasedir avoids hitting ovl_is_inuse(parent) of
		 * this instance and covers overlapping work and index dirs,
		 * unless work or index dir have been moved since created inside
		 * workbasedir.  In that case, we already have their traps in
		 * inode cache and we will catch that case on lookup.
		 */
		err = ovl_check_layer(sb, ofs, ofs->workbasedir, "workdir");	// 对于workdir，检查哈希表是否已有置上“trap”标记的ofs->workbasedir对应inode；检查ofs->workbasedir是否有“I_OVL_INUSE”标记
		if (err)
			return err;
	}

	for (i = 0; i < ofs->numlower; i++) {
		err = ovl_check_layer(sb, ofs,
				      ofs->lower_layers[i].mnt->mnt_root,
				      "lowerdir");				// 对于lower层，检查哈希表是否已有置上“trap”标记的ofs->lower_layers[i].mnt->mnt_root对应inode；检查ofs->lower_layers[i].mnt->mnt_root是否有“I_OVL_INUSE”标记
		if (err)
			return err;
	}

	return 0;
}

static int ovl_fill_super(struct super_block *sb, void *data, int silent)
{
	struct path upperpath = { };
	struct dentry *root_dentry;
	struct ovl_entry *oe;
	struct ovl_fs *ofs;							// overlay文件系统private超级块
	struct cred *cred;
	int err;

	err = -ENOMEM;
	ofs = kzalloc(sizeof(struct ovl_fs), GFP_KERNEL);
	if (!ofs)
		goto out;

	ofs->creator_cred = cred = prepare_creds();
	if (!cred)
		goto out_err;

	ofs->config.index = ovl_index_def;
	ofs->config.nfs_export = ovl_nfs_export_def;
	ofs->config.xino = ovl_xino_def();
	ofs->config.metacopy = ovl_metacopy_def;
	err = ovl_parse_opt((char *) data, &ofs->config);
	if (err)
		goto out_err;

	err = -EINVAL;
	if (!ofs->config.lowerdir) {						// overlay文件系统必须要有至少一个lower层
		if (!silent)
			pr_err("overlayfs: missing 'lowerdir'\n");
		goto out_err;
	}

	sb->s_stack_depth = 0;
	sb->s_maxbytes = MAX_LFS_FILESIZE;
	/* Assume underlaying fs uses 32bit inodes unless proven otherwise */
	if (ofs->config.xino != OVL_XINO_OFF)
		ofs->xino_bits = BITS_PER_LONG - 32;

	/* alloc/destroy_inode needed for setting up traps in inode cache */
	sb->s_op = &ovl_super_operations;					// 层间重叠检测需要新建inode，用到s_op

	if (ofs->config.upperdir) {						// 如果这个overlay文件系统实例配置了upper层
		if (!ofs->config.workdir) {					// 配置了upper层的overlay文件系统必须有workdir
			pr_err("overlayfs: missing 'workdir'\n");
			goto out_err;
		}

		err = ovl_get_upper(sb, ofs, &upperpath);			// upperpath是指定upper层的路径，upper层的vfsmount实例被clone并赋值给ofs->upper_mnt。获取upper层，检查是否已经有打上“trap”标记的inode，同时为upper层的root inode打上“trap”标记
		if (err)
			goto out_err;

		err = ovl_get_workdir(sb, ofs, &upperpath);			// 在overlay装载选项指定的$WORKDIR下创建实际工作目录work。获取workdir，检查是否已经有打上“trap”标记的inode，同时为workdir的root inode打上“trap”标记
		if (err)
			goto out_err;

		if (!ofs->workdir)
			sb->s_flags |= SB_RDONLY;

		sb->s_stack_depth = ofs->upper_mnt->mnt_sb->s_stack_depth;
		sb->s_time_gran = ofs->upper_mnt->mnt_sb->s_time_gran;		// overlay文件系统的a/c/mtime时间粒度和upper层一致

	}
	oe = ovl_get_lowerstack(sb, ofs);					// 填充ofs->lower_layers，记录lower层信息。逐个获取lower层，检查是否已经有打上“trap”标记的inode，同时为每个lower层的root inode打上“trap”标记
	err = PTR_ERR(oe);
	if (IS_ERR(oe))
		goto out_err;

	/* If the upper fs is nonexistent, we mark overlayfs r/o too */
	if (!ofs->upper_mnt)							// overlay规定lower层只读，upper层rw，没有upper层的overlay当然是只读
		sb->s_flags |= SB_RDONLY;

	if (!(ovl_force_readonly(ofs)) && ofs->config.index) {
		err = ovl_get_indexdir(sb, ofs, oe, &upperpath);
		if (err)
			goto out_free_oe;

		/* Force r/o mount with no index dir */
		if (!ofs->indexdir) {
			dput(ofs->workdir);
			ofs->workdir = NULL;
			sb->s_flags |= SB_RDONLY;
		}

	}

	err = ovl_check_overlapping_layers(sb, ofs);				// 对每个层对应root inode的parent递归检查是否已经打上“trap”标记，重叠层可能是互为祖先关系
	if (err)
		goto out_free_oe;

	/* Show index=off in /proc/mounts for forced r/o mount */
	if (!ofs->indexdir) {
		ofs->config.index = false;
		if (ofs->upper_mnt && ofs->config.nfs_export) {
			pr_warn("overlayfs: NFS export requires an index dir, falling back to nfs_export=off.\n");
			ofs->config.nfs_export = false;
		}
	}

	if (ofs->config.metacopy && ofs->config.nfs_export) {
		pr_warn("overlayfs: NFS export is not supported with metadata only copy up, falling back to nfs_export=off.\n");
		ofs->config.nfs_export = false;
	}

	if (ofs->config.nfs_export)
		sb->s_export_op = &ovl_export_operations;

	/* Never override disk quota limits or use reserved space */
	cap_lower(cred->cap_effective, CAP_SYS_RESOURCE);

	sb->s_magic = OVERLAYFS_SUPER_MAGIC;
	sb->s_xattr = ovl_xattr_handlers;
	sb->s_fs_info = ofs;
	sb->s_flags |= SB_POSIXACL;

	err = -ENOMEM;
	root_dentry = d_make_root(ovl_new_inode(sb, S_IFDIR, 0));		// 为overlay根目录申请inode和dentry，并将inode和dentry绑定，返回根目录的dentry
	if (!root_dentry)
		goto out_free_oe;

	root_dentry->d_fsdata = oe;						// 将根目录的具体文件系统相关dentry(dentry->d_fsdata)指向overlay_dentry

	mntput(upperpath.mnt);
	if (upperpath.dentry) {
		ovl_dentry_set_upper_alias(root_dentry);
		if (ovl_is_impuredir(upperpath.dentry))
			ovl_set_flag(OVL_IMPURE, d_inode(root_dentry));
	}

	/* Root is always merge -> can have whiteouts */
	ovl_set_flag(OVL_WHITEOUTS, d_inode(root_dentry));			// 根目录是一个whiteout文件
	ovl_dentry_set_flag(OVL_E_CONNECTED, root_dentry);
	ovl_set_upperdata(d_inode(root_dentry));
	ovl_inode_init(d_inode(root_dentry), upperpath.dentry,			// 根目录的ovl_inode初始化
		       ovl_dentry_lower(root_dentry), NULL);

	sb->s_root = root_dentry;						// 超级块的根目录dentry初始化

	return 0;

out_free_oe:
	ovl_entry_stack_free(oe);
	kfree(oe);
out_err:
	path_put(&upperpath);
	ovl_free_fs(ofs);
out:
	return err;
}

static struct dentry *ovl_mount(struct file_system_type *fs_type, int flags,
				const char *dev_name, void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data, ovl_fill_super);
}

static struct file_system_type ovl_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "overlay",
	.mount		= ovl_mount,
	.kill_sb	= kill_anon_super,
};
MODULE_ALIAS_FS("overlay");

static void ovl_inode_init_once(void *foo)
{
	struct ovl_inode *oi = foo;

	inode_init_once(&oi->vfs_inode);
}

static int __init ovl_init(void)
{
	int err;

	ovl_inode_cachep = kmem_cache_create("ovl_inode",
					     sizeof(struct ovl_inode), 0,
					     (SLAB_RECLAIM_ACCOUNT|
					      SLAB_MEM_SPREAD|SLAB_ACCOUNT),
					     ovl_inode_init_once);
	if (ovl_inode_cachep == NULL)
		return -ENOMEM;

	err = register_filesystem(&ovl_fs_type);
	if (err)
		kmem_cache_destroy(ovl_inode_cachep);

	return err;
}

static void __exit ovl_exit(void)
{
	unregister_filesystem(&ovl_fs_type);

	/*
	 * Make sure all delayed rcu free inodes are flushed before we
	 * destroy cache.
	 */
	rcu_barrier();
	kmem_cache_destroy(ovl_inode_cachep);

}

module_init(ovl_init);
module_exit(ovl_exit);
