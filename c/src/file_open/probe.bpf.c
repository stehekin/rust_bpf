#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "fs_walk.h"
#include "common/vmlinux.h"

char _license[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
  struct inode *inode = BPF_CORE_READ(file, f_path.dentry, d_inode);
  if (!S_ISREG(BPF_CORE_READ(inode, i_mode))) {
    return 0;
  }

  iterate_hardlinks_context ihc = {
    .list_elem = BPF_CORE_READ(inode, i_dentry.first),
  };

  bpf_loop(MAX_HARDLINKS, iterate_hardlinks, &ihc, 0);
  return 0;
}


