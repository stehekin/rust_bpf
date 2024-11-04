#ifndef _LW_TASK_H_
#define _LW_TASK_H_

#include "all.h"
#include "common/vmlinux.h"

typedef struct {
  int pid;
  int tgid;
  uint64_t start_boottime;
} lw_task_struct;

static int get_task(struct task_struct *src, lw_task_struct *target) {
  if (!src || !target) {
    return 0;
  }

  target->pid = BPF_CORE_READ(src, pid);
  target->tgid = BPF_CORE_READ(src, tgid);
  target->start_boottime = BPF_CORE_READ(src, start_boottime);

  return 0;
}

#endif