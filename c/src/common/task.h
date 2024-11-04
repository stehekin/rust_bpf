#ifndef _LW_TASK_H_
#define _LW_TASK_H_

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/macros.h"
#include "common/vmlinux.h"

typedef struct {
  int pid;
  int tgid;
  uint64_t start_boottime;
} lw_task_struct;

static int parse_task(struct task_struct *src, lw_task_struct *target) {
  if (!src || !target) {
    return 0;
  }

  target->pid = BPF_CORE_READ(src, pid);
  target->tgid = BPF_CORE_READ(src, tgid);
  target->start_boottime = BPF_CORE_READ(src, start_boottime);

  return 0;
}

#endif