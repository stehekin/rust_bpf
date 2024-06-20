#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/vmlinux.h"
#include "common/types.h"

#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)

#define MAX_HARDLINKS 8

char _license[] SEC("license") = "GPL";

typedef struct {
  struct hlist_node *list_elem;
} iterate_hardlinks_context;

static int iterate_hardlinks(__u32 index, iterate_hardlinks_context *ihc) {
  struct dentry *dentry = container_of(ihc->list_elem, struct dentry, d_u.d_alias);
  if (!dentry) {
    return BPF_LOOP_STOP;
  }

  bpf_printk("iterate_hardlinks %s", BPF_CORE_READ(dentry, d_name.name));

  ihc->list_elem = BPF_CORE_READ(dentry, d_u.d_alias.next);
  if (ihc->list_elem) {
    return BPF_LOOP_CONTINUE;
  }
  return BPF_LOOP_STOP;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
  struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);

  if (!dentry) {
    return 0;
  }

  struct inode *inode = BPF_CORE_READ(dentry, d_inode);

  if (!S_ISREG(BPF_CORE_READ(inode, i_mode))) {
    return 0;
  }


  iterate_hardlinks_context ihc = {
    .list_elem = BPF_CORE_READ(inode, i_dentry.first),
  };

  bpf_loop(MAX_HARDLINKS, iterate_hardlinks, &ihc, 0);

  return 0;
}
