#include "common/int_types.h"
#include "common/signals.h"
#include "common/str.h"
#include "common/types.h"
#include "common/vmlinux.h"
#include "common/task.h"
#include "common/blob.h"
#include "common/maps.h"

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

char _license[] SEC("license") = "GPL";

static s32 copy_str_blobstr(lw_blobstr *dest, const char *src) {
  s32 result = copy_str(dest->str, BLOBSTR_LEN , src, 0, false);
  if (result < -1) {
    return 0;
  }

  if (result == 1) {
    dest->blob.flag = 0;
    result = copy_str_to_blob(src, &dest->blob.blob_id, 0, BLOB_SIZE_256, false);
    if (result < 0) {
      dest->blob.blob_id = 0;
    }
  }

  return result;
}

// /usr/src/linux-headers-6.1.0-13-common/include/trace/events/sched.h
// TP_PROTO(struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec, struct task_struct *_ignore, pid_t old_pid, struct linux_binprm*bprm) {
  struct task_struct *current = bpf_get_current_task_btf();
  lw_task *task = bpf_task_storage_get(&_lw_task_storage, current, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
  if (!task) {
    return 0;
  }

  get_task_creds(current, &task->creds);
  get_task_proc(current, &task->pid);

  lw_exec *exec = &task->exec;
  copy_str_blobstr(&exec->filename, BPF_CORE_READ(bprm, filename));
  copy_str_blobstr(&exec->interp, (void *)BPF_CORE_READ(bprm, interp));

  submit_task(task);
  return 0;
}