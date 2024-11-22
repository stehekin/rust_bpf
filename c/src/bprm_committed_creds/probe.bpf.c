#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/blob.h"
#include "common/bprm.h"
#include "common/task.h"
#include "common/vmlinux.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, const struct linux_binprm *bprm) {
  lw_blob * blob = reserve_blob();
  if (!blob) {
    return 0;
  }

  bpf_printk("blob1 -> %s", bprm->filename);
  long l1 = bpf_core_read_str(blob->data, 100, bprm->filename);
  bpf_printk("blob1 -> %s %d", blob->data, l1);
  blob = next_blob(blob);
  if (!blob) {
    return 0;
  }
  l1 = bpf_core_read_str(blob->data, 100, bprm->filename + 100);
  bpf_printk("blob2 -> %s %d", blob->data, l1);
  submit_blob(blob);
  return 0;
}