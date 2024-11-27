#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/signals.h"
#include "common/types.h"
#include "common/vmlinux.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/bprm_committed_creds")
int BPF_PROG(bprm_committed_creds, const struct linux_binprm *bprm) {
  struct task_struct *current = bpf_get_current_task_btf();
  lw_signal_task signal_task = {0};
  set_signal_header(&signal_task.header, SIGNAL_TASK);
  const struct cred *cred = BPF_CORE_READ(current, real_cred);
  set_creds(&signal_task.creds, cred);



  return 0;
}