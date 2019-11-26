/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

struct mnt_namespace {
	atomic_t		count;
	struct ns_common	ns;
	struct mount *	root;							// mount命名空间的根文件系统对应的装载实例
	struct list_head	list;						// mount命名空间下的mount实例都被链入list
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		mounts; /* # of mounts in the namespace */	// 该命名空间下已经mount的装载实例
	unsigned int		pending_mounts;
} __randomize_layout;

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mountpoint {
	struct hlist_node m_hash;						// 挂载点节点全局哈希表
	struct dentry *m_dentry;						// 挂载点节点对应的挂载路径dentry(/mnt)
	struct hlist_head m_list;
	int m_count;								// 挂载点节点引用计数
};

struct mount {
	struct hlist_node mnt_hash;						// 全局挂载实例哈希表，不包括系统根挂载实例
	struct mount *mnt_parent;						// 指向父挂载实例，例如挂载实例A对应文件系统挂载到挂载实例B对应文件系统的/mnt下，A的parent就是B，系统根挂载实例指向自己
	struct dentry *mnt_mountpoint;						// 指向被挂载文件系统装载实例对应的目录项，例如/mnt的dentry
	struct vfsmount mnt;							// vfsmount（本挂载实例对应文件系统信息）
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;					// 链入到mnt_namespace的list域，代表同一mount命名空间的挂载实例
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;								// 引用计数
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */	// 指向装载到本挂载实例对应文件系统下的子文件系统挂载实例链表
	struct list_head mnt_child;	/* and going through their mnt_child */	// 如果挂载实例有parent，链入parent挂载实例的mnt_mounts
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */	// 设备名，例如/dev/sda
	struct list_head mnt_list;						// 链入mount namespace的list链表，代表属于同一mnt namespace
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */	// 链入peer group链表
	struct list_head mnt_slave_list;/* list of slave mounts */		// 指向该装载实例下的slave group链表
	struct list_head mnt_slave;	/* slave list entry */			// 链入某个slave group链表
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */// 该装载实例的master
	struct mnt_namespace *mnt_ns;	/* containing namespace */		// 指向挂载实例所处的mount命名空间
	struct mountpoint *mnt_mp;	/* where is it mounted */		// 挂载点节点
	union {
		struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
		struct hlist_node mnt_umount;
	};
	struct list_head mnt_umounting; /* list entry for umount propagation */
#ifdef CONFIG_FSNOTIFY
	struct fsnotify_mark_connector __rcu *mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */			// mount id
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct hlist_head mnt_stuck_children;
} __randomize_layout;

#define MNT_NS_INTERNAL ERR_PTR(-EINVAL) /* distinct from any mnt_namespace */

static inline struct mount *real_mount(struct vfsmount *mnt)
{
	return container_of(mnt, struct mount, mnt);
}

static inline int mnt_has_parent(struct mount *mnt)
{
	return mnt != mnt->mnt_parent;
}

static inline int is_mounted(struct vfsmount *mnt)
{
	/* neither detached nor internal? */
	return !IS_ERR_OR_NULL(real_mount(mnt)->mnt_ns);
}

extern struct mount *__lookup_mnt(struct vfsmount *, struct dentry *);

extern int __legitimize_mnt(struct vfsmount *, unsigned);
extern bool legitimize_mnt(struct vfsmount *, unsigned);

static inline bool __path_is_mountpoint(const struct path *path)
{
	struct mount *m = __lookup_mnt(path->mnt, path->dentry);
	return m && likely(!(m->mnt.mnt_flags & MNT_SYNC_UMOUNT));
}

extern void __detach_mounts(struct dentry *dentry);

static inline void detach_mounts(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return;
	__detach_mounts(dentry);
}

static inline void get_mnt_ns(struct mnt_namespace *ns)
{
	atomic_inc(&ns->count);
}

extern seqlock_t mount_lock;

static inline void lock_mount_hash(void)
{
	write_seqlock(&mount_lock);
}

static inline void unlock_mount_hash(void)
{
	write_sequnlock(&mount_lock);
}

struct proc_mounts {
	struct mnt_namespace *ns;
	struct path root;
	int (*show)(struct seq_file *, struct vfsmount *);
	void *cached_mount;
	u64 cached_event;
	loff_t cached_index;
};

extern const struct seq_operations mounts_op;

extern bool __is_local_mountpoint(struct dentry *dentry);
static inline bool is_local_mountpoint(struct dentry *dentry)
{
	if (!d_mountpoint(dentry))
		return false;

	return __is_local_mountpoint(dentry);
}

static inline bool is_anon_ns(struct mnt_namespace *ns)
{
	return ns->seq == 0;
}
