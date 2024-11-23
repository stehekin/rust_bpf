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
#include "common/signal.h"
#include "common/vmlinux.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, const struct linux_binprm *bprm) {
  lw_blob * blob = reserve_blob();
  if (!blob) {
    return 0;
  }

  long l1 = bpf_core_read_str(blob->data, 100, bprm->filename);
  blob = next_blob(blob);
  if (!blob) {
    return 0;
  }
  l1 = bpf_core_read_str(blob->data, 100, bprm->filename + 100);
  submit_blob(blob);
  return 0;
}