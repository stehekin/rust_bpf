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

#define BLOB_SIZE_LARGE 1024
#define BLOB_SIZE_SMALL 512
#define BLOB_MAP_ENTRIES 1024 * BLOB_SIZE_LARGE

typedef struct {
  uint8_t version;
  // Size of the blob.
  uint8_t blob_size;
  // Size of the effective data in the blob;
  uint16_t data_size;
  uint32_t reserved;
  uint64_t blob_id;
  uint64_t blob_next;
} lw_blob_header;

typedef struct {
  lw_blob_header header;
  uint8_t data[BLOB_SIZE_LARGE - sizeof(lw_blob_header)];
} lw_blob_large;

typedef struct {
  lw_blob_header header;
  // Must update BLOB_DATA_SIZE if updating lw_blob.
  uint8_t data[BLOB_SIZE_SMALL - sizeof(lw_blob_header)];
} lw_blob_small;

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

static void* _reserve_blob(uint64_t blob_size) {
  uint32_t zero = 0;
  uint64_t* blob_id = bpf_map_lookup_elem(&_blob_index_, &zero);
  if (!blob_id) {
    // Cannot happen.
    return 0;
  }

  void *blob = bpf_ringbuf_reserve(&_blob_ringbuf_, blob_size, 0);
  if (!blob) {
    return 0;
  }

  lw_blob_header *header = (void *)blob;

  header-> version = 0x01;
  header->data_size = 0;
  header->blob_id = *blob_id;
  header->blob_next = 0;

  *blob_id = *blob_id + 1;
  bpf_map_update_elem(&_blob_index_, &zero, blob_id, BPF_ANY);

  return blob;
}

static inline lw_blob_header* reserve_blob(uint8_t is_large) {
  if (is_large) {
    return _reserve_blob(sizeof(lw_blob_large));
  } else {
    return _reserve_blob(sizeof(lw_blob_small));
  }
}

static inline void submit_blob(void *blob) {
  bpf_ringbuf_submit(blob, 0);
}

static inline void discard_blob(void *blob) {
  bpf_ringbuf_discard(blob, 0);
}

// `next_blob_(large|small)` reserves a new blob and links it to `blob`.
// `next_blob_(large|small)` submits the given `blob`.
static inline lw_blob_header *_next_blob(lw_blob_header *blob_header, uint8_t is_large) {
  if (!blob_header) {
    return 0;
  }

  lw_blob_header *next_header = reserve_blob(is_large);
  if (next_header) {
    blob_header->blob_next = next_header->blob_id;
  }

  submit_blob(blob_header);
  return next_header;
}


static inline lw_blob_header* next_blob_large(lw_blob_large *blob) {
  return _next_blob(, uint8_t is_large)
}

static inline lw_blob_header* next_blob_small(lw_blob_small *blob) {
  if (!blob) {
    return 0;
  }

  lw_blob_header *next_blob = reserve_blob_small();
  if (next_blob) {
    blob->header.blob_next = next_blob->blob_id;
  }

  submit_blob(blob);
  return next_blob;
}


// `copy_str_to_blob` copies str to blobs. This function returns
// * 0 if it has succeeded;
// * -1 if it has failed;
//
// `blob_id` is the first blob submitted, even if the function has failed.
// If no blobs are submitted, `blob_id` is -1.
// `str_len` is the length of the str successfully copied.
//
// The last byte of all blobs submitted is NUL.
//
// Maximum blobs supported by this function is 16.
#define MAX_BLOBS 16
static inline int32_t copy_str_to_blob(const void *str, uint64_t *blob_id, long *str_len, bool use_large) {
  int32_t rv = -1;
  if (!str || !blob_id || !str_len) {
    return -1;
  }

  long total_copied = 0;

  lw_blob * blob = reserve_blob();
  for (uint16_t i = 0; i < MAX_BLOBS && blob; i++) {
    if (i == 0) {
      *blob_id = blob->blob_id;
    }

    long len = bpf_probe_read_kernel_str(blob->data, BLOB_DATA_SIZE, str + total_copied);

    if (len < 0) {
      break;
    } else if (len < BLOB_DATA_SIZE) {
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
      *str_len = total_copied;
      submit_blob(blob);
    } else {
      discard_blob(blob);
    }
  }

  return rv;
}

// `copy_str` copies str to the `dest`. This function returns
// * 0 if it has succeeded and all bytes in the `str` are copied (NUL included);
// * -1 if it has failed;
// * 1 if it has succeeded but not all bytes in the `str` has copied;
//
// `str_len` is the length of the str successfully copied.
static inline int32_t copy_str(uint8_t *dest, uint16_t size, const void *str, long *str_len) {
  if (!dest || !size || !str || !str_len) {
    return -1;
  }

  long len = bpf_probe_read_kernel_str(dest, size, str);
  *str_len = len;
  if (len < 0) {
    return -1;
  } else if (len < size) {
    return 0;
  }

  // len == size
  uint8_t last;
  bpf_probe_read_kernel(&last, 1, str + len - 1);
  if (last == 0) {
    return 0;
  } else {
    return 1;
  }
}

#endif