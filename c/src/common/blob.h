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
#define BLOB_DATA_SIZE (BLOB_SIZE - 24)

typedef struct {
  uint16_t version;
  uint16_t data_size;
  uint32_t reserved;
  uint64_t blob_id;
  uint64_t blob_next;
  // Must update BLOB_DATA_SIZE if updating lw_blob.
  uint8_t data[BLOB_DATA_SIZE];
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

// `next_blob` reserves a new blob and links it to `blob`.
// `next_blob` submits the given `blob`.
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

// `copy_str` copies str to blobs. This function
// * returns 0 if it has succeeded;
// * returns -1 if it has failed.
//
// `blob_id` is the first blob submitted, even if the function has failed.
// If no blobs are submitted, `blob_id` is -1.
//
// The last byte of all blobs submitted is NUL.
//
// Maximum blobs supported by this function is 256.
#define MAX_BLOBS 256
static inline int32_t copy_str_to_blob(uint8_t *str, uint64_t *blob_id) {
  int32_t rv = -1;
  long total_copied = 0;

  lw_blob * blob = reserve_blob();
  for (uint16_t i = 0; i < MAX_BLOBS && blob; i++) {
    if (i == 0) {
      *blob_id = blob->blob_id;
    }

    long l1 = bpf_probe_read_kernel_str(blob->data, BLOB_DATA_SIZE, str + total_copied);

    if (l1 < 0) {
      break;
    } else if (l1 < BLOB_DATA_SIZE) {
      rv = 0;
      break;
    }

    total_copied += BLOB_DATA_SIZE - 1;

    uint8_t last;
    bpf_probe_read_kernel(&last, 1, str + total_copied);
    // No more blobs needed.
    if (last == 0) {
      rv = 0;
      break;
    }

    if (i == MAX_BLOBS - 1) {
      submit_blob(blob);
      blob = 0;
      break;
    }

    blob = next_blob(blob);
  }

  if (blob) {
    if (rv == 0) {
      submit_blob(blob);
    } else {
      discard_blob(blob);
    }
  }

  return rv;
}

#endif