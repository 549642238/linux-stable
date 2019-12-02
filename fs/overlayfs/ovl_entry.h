/* SPDX-License-Identifier: GPL-2.0-only */
/*
 *
 * Copyright (C) 2011 Novell Inc.
 * Copyright (C) 2016 Red Hat, Inc.
 */

struct ovl_config {								// 配置，从用户态传入参数解析得到该结构体
	char *lowerdir;
	char *upperdir;
	char *workdir;
	bool default_permissions;
	bool redirect_dir;
	bool redirect_follow;
	const char *redirect_mode;
	bool index;
	bool nfs_export;
	int xino;
	bool metacopy;
};

struct ovl_sb {
	struct super_block *sb;
	dev_t pseudo_dev;
};

struct ovl_layer {
	struct vfsmount *mnt;							// 该层对应系统克隆的vfsmount
	/* Trap in ovl inode cache */
	struct inode *trap;							// 存放改成打上“trap”标记的root inode
	struct ovl_sb *fs;
	/* Index of this layer in fs root (upper idx == 0) */
	int idx;
	/* One fsid per unique underlying sb (upper fsid == 0) */
	int fsid;
};

struct ovl_path {
	struct ovl_layer *layer;
	struct dentry *dentry;
};

/* private information held for overlayfs's superblock */
struct ovl_fs {
	struct vfsmount *upper_mnt;						// 如果有upper层，根目录指向从upper层文件系统克隆的vfsmount
	unsigned int numlower;							// 有几个lower层，没有则为0
	/* Number of unique lower sb that differ from upper sb */
	unsigned int numlowerfs;
	struct ovl_layer *lower_layers;						// 每个lower层信息，没有则为NULL
	struct ovl_sb *lower_fs;
	/* workbasedir is the path at workdir= mount option */
	struct dentry *workbasedir;						// overlay挂载选项中'-o workdir=$WORKDIR'指定工作目录$WORKDIR对应的dentry
	/* workdir is the 'work' directory under workbasedir */
	struct dentry *workdir;							// 实际工作目录的dentry，指向$WORKDIR/work
	/* index directory listing overlay inodes by origin file handle */
	struct dentry *indexdir;
	long namelen;								// 保存所有lower层和upper层对应路径的目标文件名最大长度
	/* pathnames of lower and upper dirs, for show_options */
	struct ovl_config config;						// overlay装载参数(upperdir、lowerdir等)，从用户态解析得到
	/* creds of process who forced instantiation of super block */
	const struct cred *creator_cred;
	bool tmpfile;
	bool noxattr;
	/* Did we take the inuse lock? */
	bool upperdir_locked;
	bool workdir_locked;
	/* Traps in ovl inode cache */
	struct inode *upperdir_trap;						// upper层置上“trap”标记的root inode
	struct inode *workbasedir_trap;						// $WORKDIR置上“trap”标记的inode
	struct inode *workdir_trap;						// $WORKDIR/work置上“trap”标记的inode
	struct inode *indexdir_trap;
	/* Inode numbers in all layers do not use the high xino_bits */
	unsigned int xino_bits;
};

/* private information held for every overlayfs dentry */
struct ovl_entry {
	union {
		struct {
			unsigned long flags;
		};
		struct rcu_head rcu;
	};
	unsigned numlower;							// 该文件在几个lower层存在，如果所有lower层都没有该文件则numlower=0，对于根目录文件所有lower层都要计数
	struct ovl_path lowerstack[];						// 该文件在所有lower层的记录（例如对应lower层的dentry）
};

struct ovl_entry *ovl_alloc_entry(unsigned int numlower);

static inline struct ovl_entry *OVL_E(struct dentry *dentry)
{
	return (struct ovl_entry *) dentry->d_fsdata;
}

struct ovl_inode {
	union {
		struct ovl_dir_cache *cache;	/* directory */
		struct inode *lowerdata;	/* regular file */
	};
	const char *redirect;
	u64 version;
	unsigned long flags;
	struct inode vfs_inode;
	struct dentry *__upperdentry;						// 记录upper层dentry。如果该文件在upper层存在__upperdentry指向upper层dentry；如果该文件只存在lower层，则__upperdentry为NULL
	struct inode *lower;							// 记录该文件出现在第一个lower层的inode，如果没有lower层存在则为NULL

	/* synchronize copy up and more */
	struct mutex lock;
};

static inline struct ovl_inode *OVL_I(struct inode *inode)
{
	return container_of(inode, struct ovl_inode, vfs_inode);
}

static inline struct dentry *ovl_upperdentry_dereference(struct ovl_inode *oi)
{
	return READ_ONCE(oi->__upperdentry);
}
