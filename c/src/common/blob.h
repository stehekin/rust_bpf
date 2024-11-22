#ifndef _LW_BLOB_H_
#define _LW_BLOB_H_

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define BLOB_SIZE 1024
#define BLOB_MAP_ENTRIES 1024 * BLOB_SIZE

typedef struct _lw_blob_ {
  uint16_t version;
  uint16_t data_size;
  uint32_t reserved;
  uint64_t blob_id;
  uint64_t blob_next;
  uint8_t data[BLOB_SIZE - 24];
} lw_blob;

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, uint32_t);
  __type(value, uint64_t);
  __uint(max_entries, 1);
} _blob_index_ SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, BLOB_MAP_ENTRIES);
} _blob_ringbuf_ SEC(".maps");

static inline lw_blob* reserve_blob() {
  uint32_t zero = 0;
  uint64_t* blob_id = bpf_map_lookup_elem(&_blob_index_, &zero);
  if (!blob_id) {
    // Cannot happen.
    return 0;
  }

  lw_blob *blob = bpf_ringbuf_reserve(&_blob_ringbuf_, sizeof(lw_blob), 0);
  if (!blob) {
    return 0;
  }

  blob-> version = 0x01;
  blob->data_size = 0;
  blob->blob_id = *blob_id;
  blob->blob_next = 0;

  *blob_id = *blob_id + 1;
  bpf_map_update_elem(&_blob_index_, &zero, blob_id, BPF_ANY);

  return blob;
}

static inline void submit_blob(lw_blob *blob) {
  bpf_ringbuf_submit(blob, 0);
}

static inline void discard_blob(lw_blob *blob) {
  bpf_ringbuf_discard(blob, 0);
}

static inline lw_blob* next_blob(lw_blob *blob) {
  if (!blob) {
    return 0;
  }

  lw_blob *next_blob = reserve_blob();
  if (next_blob) {
    blob->blob_next = next_blob->blob_id;
  }

  submit_blob(blob);
  return next_blob;
}

#endif