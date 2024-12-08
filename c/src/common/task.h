#ifndef __LW_TASK_H__
#define __LW_TASK_H__

#include "common/int_types.h"
#include "common/vmlinux.h"
#include "common/namespace.h"
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

#endif