#ifndef _LW_SIGNALS_H_
#define _LW_SIGNALS_H_

//
// `types.h` defines the structures of data passing from the ebpf to the userspace.
//

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
#include "types.h"

static inline void set_signal_header(lw_signal_header *header, lw_signal_type type) {
  if (!header) {
    return;
  }

  header->version = 0x01;
  header->type = type;
  header->cpu_id = bpf_get_smp_processor_id();
  header->reserved = 0;
  header->signal_time_ns = bpf_ktime_get_boot_ns();
}

static inline void set_creds(lw_creds *dest, const struct cred *src) {
  if (!dest) {
    return;
  }

  BPF_CORE_READ_INTO(&dest->egid, src, egid);
  BPF_CORE_READ_INTO(&dest->gid, src, gid);
  BPF_CORE_READ_INTO(&dest->euid, src, euid);
  BPF_CORE_READ_INTO(&dest->uid, src, uid);
}

static u64

#endif
