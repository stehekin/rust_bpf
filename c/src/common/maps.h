#ifndef __LW_MAPS_H__
#define __LW_MAPS_H__

#include "common/types.h"

#include <linux/bpf.h>
#include <bpf_core_read.h>

#define BLOB_MAP_ENTRIES 1024 * BLOB_SIZE_MAX
#define SIGNAL_MAP_ENTRIES 1024 * 1024

// `_blob_index_` is a per cpu array that saves the next blob id.
// Blob is a 64-bit integer, with the first 16 bits as the cpu_id.
// So the max cpu number supported is 2^16 ;-)
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u64);
  __uint(max_entries, 1);
} _blob_index_ SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, BLOB_MAP_ENTRIES);
} _blob_ringbuf_ SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, u32);
  __type(value, lw_task);
} _lw_task_storage SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, SIGNAL_MAP_ENTRIES);
} _signal_ringbuf_ SEC(".maps");

#endif