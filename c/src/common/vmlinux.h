#ifndef _NENP_COMMON_VMLINUX_H_
#define _NENP_COMMON_VMLINUX_H_

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)),           \
                             apply_to = record)
#endif

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

enum {
  false = 0,
  true = 1,
};

typedef u32 __kernel_dev_t;
typedef __kernel_dev_t dev_t;
#define __dev_t_defined

typedef unsigned int fmode_t;

typedef struct {
  unsigned int val;
} kuid_t;

struct list_head {
        struct list_head *next;
        struct list_head *prev;
};

struct hlist_bl_node {
  struct hlist_bl_node *next, **pprev;
};

struct hlist_head {
  struct hlist_node *first;
};

struct hlist_node {
  struct hlist_node *next;
  struct hlist_node **pprev;
};

struct qstr {
  u32 len;
  const unsigned char *name;
};

struct cred {
  kuid_t uid;
  kuid_t euid;
  kuid_t gid;
  kuid_t egid;
};

struct super_block {
  dev_t s_dev;
  unsigned long s_magic;
};

struct inode {
  unsigned short i_mode;
  kuid_t i_uid;
  kuid_t i_gid;
  unsigned long i_ino;
  struct super_block *i_sb;
  dev_t i_rdev;
  union {
    struct hlist_head i_dentry;
  };
  union {
    struct pipe_inode_info *i_pipe;
  };
};

struct dentry {
  struct inode *d_inode;
  struct hlist_bl_node d_hash;
  struct dentry *d_parent;
  struct qstr d_name;
  union {
    struct hlist_node d_alias;
  } d_u;
};
struct path {
  struct vfsmount *mnt;
  struct dentry *dentry;
};

struct file {
  fmode_t f_mode;
  struct inode *f_inode;
  struct path f_path;
  unsigned int f_flags;
  void *private_data;
};

struct linux_binprm {
  struct file *file;
  int argc;
  int envc;
};

struct fdtable {
  unsigned int max_fds;
  struct file **fd; // __rcu.
};

struct ns_common {
  unsigned int inum;
};

struct user_namespace {
  struct ns_common ns;
};

struct uts_namespace {
  struct ns_common ns;
};

struct ipc_namespace {
  struct ns_common ns;
};

struct mnt_namespace {
  struct ns_common ns;
  struct list_head list;
  struct user_namespace *user_ns;
};

struct pid_namespace {
  struct ns_common ns;
  unsigned int level;
};

struct upid {
  int nr;
  struct pid_namespace *ns;
};

struct pid {
  unsigned int level;
  struct upid numbers[1];
};

struct net {
  struct ns_common ns;
  u64 net_cookie;
};

struct time_namespace {
  struct ns_common ns;
};

struct cgroup_namespace {
  struct ns_common ns;
};

struct nsproxy {
  struct uts_namespace *uts_ns;
  struct ipc_namespace *ipc_ns;
  struct mnt_namespace *mnt_ns;
  struct pid_namespace *pid_ns_for_children;
  struct net *net_ns;
  struct time_namespace *time_ns;
  struct time_namespace *time_ns_for_children;
  struct cgroup_namespace *cgroup_ns;
};

struct files_struct {
  struct fdtable *fdt; // __rcu.
};

struct mm_struct {
  struct file *exe_file; // __rcu.
};

struct task_struct {
  int pid;
  int tgid;
  kuid_t loginuid;
  struct task_struct *group_leader;
  const struct cred *real_cred;    // __rcu.
  struct task_struct *parent;      // __rcu.
  struct task_struct *real_parent; // __rcu.
  // Deprecated. Use start_boottime if it exists.
  u64 real_start_time;
  u64 start_boottime;
  struct files_struct *files;
  struct mm_struct		*mm;
  struct pid *thread_pid;
  struct nsproxy *nsproxy;
};

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute pop
#endif

#endif