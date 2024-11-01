#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/macros.h"
#include "common/vmlinux.h"

#define MAX_HARDLINKS 8
#define MAX_PATH_DEPTH 32

typedef struct {
  struct dentry *dentry;
  __u32 depth;
} iterate_fstree_context;

typedef struct {
  struct hlist_node *list_elem;
} iterate_hardlinks_context;

#define MAX_DFS_STACK_ENTRIES 1024

static int iterate_fstree(__u32 index, iterate_fstree_context *ifc) {
  struct dentry *dentry = ifc->dentry;
  if (!dentry) {
    return BPF_LOOP_STOP;
  }

  bpf_printk("filename: %s", BPF_CORE_READ(dentry, d_name.name));

  struct inode *inode = BPF_CORE_READ(dentry, d_inode);
  if (!inode) {
    return BPF_LOOP_STOP;
  }

  if (inode == BPF_CORE_READ(inode, i_sb, s_root, d_inode)) {
    return BPF_LOOP_STOP;
  }

  ifc->dentry = BPF_CORE_READ(dentry, d_parent);
  ifc->depth += 1;

  return BPF_LOOP_CONTINUE;
}

static int iterate_hardlinks(__u32 index, iterate_hardlinks_context *ihc) {
  struct dentry *dentry = container_of(ihc->list_elem, struct dentry, d_u.d_alias);
  if (!dentry) {
    return BPF_LOOP_STOP;
  }

  iterate_fstree_context ifc = {
    .dentry = dentry,
    .depth = 0,
  };
  bpf_loop(MAX_PATH_DEPTH, iterate_fstree, &ifc, 0);

  ihc->list_elem = BPF_CORE_READ(dentry, d_u.d_alias.next);
  if (ihc->list_elem) {
    return BPF_LOOP_CONTINUE;
  }

  return BPF_LOOP_STOP;
}