#ifndef __LW_TASK_H__
#define __LW_TASK_H__

#include "common/types.h"
#include "common/vmlinux.h"
#include <bpf_core_read.h>
#include <bpf_helpers.h>

// get_task_pid_vnr returns the virtual (not global) pid.
static u32 get_task_pid_vnr(const struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  u32 level = BPF_CORE_READ(pid, level);
  return BPF_CORE_READ(pid, numbers[level].nr);
}

static u32 get_task_pid_ns_id(const struct task_struct *task) {
  struct pid *pid = BPF_CORE_READ(task, thread_pid);
  u32 level = BPF_CORE_READ(pid, level);
  struct pid_namespace *ns = BPF_CORE_READ(pid, numbers[level].ns);
  return BPF_CORE_READ(ns, ns.inum);
}

static void get_task_creds(const struct task_struct *task, lw_creds *c) {
  if (!c) {
    return;
  }
  const struct cred *cred = BPF_CORE_READ(task, real_cred);
  c->gid = BPF_CORE_READ(cred, gid.val);
  c->uid = BPF_CORE_READ(cred, uid.val);
  c->egid = BPF_CORE_READ(cred, egid.val);
  c->euid = BPF_CORE_READ(cred, euid.val);
}

#endif