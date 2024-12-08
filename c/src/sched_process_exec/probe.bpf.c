#include "common/vmlinux.h"
#include "common/blob.h"

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("raw_tracepoint/sched_process_exec")
int BPF_PROG(sched_process_exec) {
  struct task_struct *current = bpf_get_current_task_btf();

  u64 blob_id;
  u64 start;
  u64 end;

  BPF_CORE_READ_INTO(&start, current, mm, arg_start);
  BPF_CORE_READ_INTO(&end, current, mm, arg_end);

  copy_data_to_blob((void *)start, end - start /* +1 ?*/, &blob_id, 0);

  // bpf_printk("[DEBUG] %ld, %ld", start, end);

  return 0;
}