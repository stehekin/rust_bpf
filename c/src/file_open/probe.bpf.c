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

char _license[] SEC("license") = "GPL";

typedef struct {
  uint64_t s_dev;
  uint64_t i_ino;
} fo_inode;

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10);
	__type(key, fo_inode);
	__type(value, uint64_t);
} fo_inode_map SEC(".maps");

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file) {
  uint64_t inode = BPF_CORE_READ(file, f_inode, i_ino);
  uint64_t dev_t = BPF_CORE_READ(file, f_inode, i_sb, s_dev);

  fo_inode node = {
    .i_ino = inode,
    .s_dev = dev_t,
  };

  uint64_t *value = bpf_map_lookup_elem(&fo_inode_map, &node);
  if (!value) {
    bpf_printk("not found %d %d", inode, dev_t);
  } else {
    bpf_printk("found");
  }

  return 0;
}