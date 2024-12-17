#ifndef __LW_TASK_H__
#define __LW_TASK_H__

#include "common/types.h"
#include "common/blob.h"
#include "common/vmlinux.h"
#include <bpf_core_read.h>
#include <bpf_helpers.h>

// get_task_pid_vnr returns the virtual (not global) pid.
static inline u32 get_task_pid_vnr(const struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  u32 level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static inline u32 get_task_pid_ns_id(const struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  u32 level = BPF_CORE_READ(pid, level);
  struct pid_namespace *ns = BPF_CORE_READ(pid, numbers[level].ns);
  return BPF_CORE_READ(ns, ns.inum);
}

static inline void get_task_creds(const struct task_struct *task, lw_creds *c) {
  const struct cred *cred = BPF_CORE_READ(task, real_cred);
  c->gid = BPF_CORE_READ(cred, gid.val);
  c->uid = BPF_CORE_READ(cred, uid.val);
  c->egid = BPF_CORE_READ(cred, egid.val);
  c->euid = BPF_CORE_READ(cred, euid.val);
}

static inline void get_task_proc(const struct task_struct *task, lw_pid *pids) {
  pids->pid = BPF_CORE_READ(task, pid);
  pids->tgid = BPF_CORE_READ(task, tgid);
  pids->pid_ns = get_task_pid_ns_id(task);
  pids->pid_vnr = get_task_pid_vnr(task);
}

static inline void get_task_parent(const struct task_struct *parent_task, lw_parent *parent) {
  parent->pid = BPF_CORE_READ(parent_task, pid);
  parent->tgid = BPF_CORE_READ(parent_task, tgid);
  parent->boot_ns = BPF_CORE_READ(parent_task, start_boottime);
}

// copy_env(&exec->env, current);
//   copy_args(&exec->args, current);

#endif