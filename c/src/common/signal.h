#ifndef _LW_SIGNAL_H_
#define _LW_SIGNAL_H_

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/vmlinux.h"

#define MAX_FILENAME 128

typedef struct {
  uint32_t uid;
  uint32_t gid;
  uint32_t euid;
  uint32_t egid;
} lw_creds;

typedef struct {
  uint32_t pid;
  uint32_t tgid;
  uint64_t start_boottime;
  uint32_t ppid;
  uint32_t rpid;
  // str_flag determines if filename and interp are blob ids or strings.
  uint64_t str_flag;
  uint8_t filename[MAX_FILENAME];
  uint8_t interp[MAX_FILENAME];
} lw_task;

/// Signal definitions.
typedef struct {
  uint16_t version;
  uint16_t type;
  uint32_t reserved;
} lw_signal_header;

typedef struct {
  lw_signal_header header;
  lw_creds creds;
  lw_task task;
} lw_signal_task;

static int parse_task(struct task_struct *src, lw_task *target) {
  if (!src || !target) {
    return 0;
  }

  target->pid = BPF_CORE_READ(src, pid);
  target->tgid = BPF_CORE_READ(src, tgid);
  target->start_boottime = BPF_CORE_READ(src, start_boottime);

  return 0;
}

#endif