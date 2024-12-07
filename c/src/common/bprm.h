#ifndef __LW_BPRM_H__
#define __LW_BPRM_H__

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/vmlinux.h"

static int parse_binprm(const struct linux_binprm *bprm) {
  bpf_printk("bprm.interp = %s", BPF_CORE_READ(bprm, interp));
  bpf_printk("bprm.filename = %s", BPF_CORE_READ(bprm, filename));
  return 0;
}

#endif