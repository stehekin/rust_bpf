#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include "common/int_types.h"

#ifndef BPF_NO_PRESERVE_ACCESS_INDEX
#pragma clang attribute push(__attribute__((preserve_access_index)),           \
                             apply_to = record)
#endif

#if defined(__TARGET_ARCH_x86)

struct thread_info {
    u32 status;
};

struct pt_regs {
    long unsigned int r15;
    long unsigned int r14;
    long unsigned int r13;
    long unsigned int r12;
    long unsigned int bp;
    long unsigned int bx;
    long unsigned int r11;
    long unsigned int r10;
    long unsigned int r9;
    long unsigned int r8;
    long unsigned int ax;
    long unsigned int cx;
    long unsigned int dx;
    long unsigned int si;
    long unsigned int di;
    long unsigned int orig_ax;
    long unsigned int ip;
    long unsigned int cs;
    long unsigned int flags;
    long unsigned int sp;
    long unsigned int ss;
};

#elif defined(__TARGET_ARCH_arm64)

struct thread_info {
    long unsigned int flags;
};

struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            u64 regs[31];
            u64 sp;
            u64 pc;
            u64 pstate;
        };
    };
    u64 orig_x0;
    s32 syscallno;
    u32 unused2;
    u64 orig_addr_limit;
    u64 pmr_save;
    u64 stackframe[2];
    u64 lockdep_hardirqs;
    u64 exit_rcu;
};

#endif

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
  struct dentry *s_root;
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
  struct cred *cred;
  int argc;
  int envc;
  struct mm_struct *mm;
  const char * filename;
  const char * interp;
};

struct fdtable {
  unsigned int max_fds;
  struct file **fd; // __rcu.
};

struct ns_common {
  unsigned int inum;
};

struct new_utsname {
    char nodename[65];
};

struct user_namespace {
  struct ns_common ns;
};

struct uts_namespace {
  struct new_utsname name;
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
  unsigned long arg_start;
  unsigned long arg_end;
  unsigned long env_start;
  unsigned long env_end;
};

struct task_struct {
  struct thread_info thread_info;
  unsigned int flags;
  int pid;
  int tgid;
  kuid_t loginuid;
  struct task_struct *group_leader;
  const struct cred *real_cred;    // __rcu.
  struct task_struct *parent;      // __rcu.
  struct task_struct *real_parent; // __rcu.
  u64 start_time;
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