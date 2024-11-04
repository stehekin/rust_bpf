#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/bprm.h"
#include "common/task.h"
#include "common/vmlinux.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, const struct linux_binprm *bprm) {
  struct task_struct *curr = bpf_get_current_task_btf();
  lw_task_struct lw_task;
  parse_task(curr, &lw_task);
  parse_binprm(bprm);
  return 0;
}