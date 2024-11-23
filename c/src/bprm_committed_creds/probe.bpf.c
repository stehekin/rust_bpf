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
#include "common/vmlinux.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, const struct linux_binprm *bprm) {
  uint64_t blob_id;
  copy_str_to_blob(bprm->filename, &blob_id);
  return 0;
}