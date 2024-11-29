#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/blob.h"
#include "common/types.h"
#include "common/vmlinux.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, const struct linux_binprm *bprm) {
  struct task_struct *current = bpf_get_current_task_btf();
  // lw_signal_task signal_task = {0};
  // set_signal_header(&signal_task.header, SIGNAL_TASK);
  // const struct cred *cred = BPF_CORE_READ(current, real_cred);
  // set_creds(&signal_task.creds, cred);

  u64 blob_id;
  u64 start;
  u64 end;

  BPF_CORE_READ_INTO(&start, current, mm, arg_start);
  BPF_CORE_READ_INTO(&end, current, mm, arg_end);

  // copy_data_to_blob((void *)start, end - start + 1, &blob_id, 0);

  bpf_printk("[DEBUG] %ld %ld", start, end);

  return 0;
}