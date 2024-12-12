#ifndef __LW_SIGNALS_H__
#define __LW_SIGNALS_H__

#include "common/types.h"
#include "common/macros.h"
#include "common/maps.h"
#include <bpf_core_read.h>
#include <bpf_helpers.h>

#define SIGNAL_VERSION 0x01

static inline void init_header(lw_sigal_header *header, lw_signal_type signal_type) {
  header->version = SIGNAL_VERSION;
  header->signal_type = signal_type;
  header->cpu_id = bpf_get_smp_processor_id();
  header->submit_time_ns = KTIME_NS();
  header->reserved = 0;
}

static inline void submit_task(const lw_task *task) {
  lw_signal_task *signal_task = bpf_ringbuf_reserve(&_signal_ringbuf_, sizeof(lw_signal_task), 0);
  if (!signal_task) {
    return;
  }

  init_header(&signal_task->header, LW_SIGNAL_TASK);
  __builtin_memcpy(&signal_task->body, task, sizeof(lw_task));
  bpf_printk("submitting task %d %s", signal_task->body.pid.pid, signal_task->body.exec.filename.str);
  bpf_ringbuf_submit(signal_task, 0);
}

#endif