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

#define BLOB_SIZE_1024 1024
#define BLOB_SIZE_512 512
#define BLOB_SIZE_256 256

#define BLOB_MAP_ENTRIES 1024 * BLOB_SIZE_1024

typedef enum  {
  SIZE_256,
  SIZE_512,
  SIZE_1024,
} BLOB_SIZE;

typedef struct {
  uint8_t version;
  BLOB_SIZE blob_size;
  // Size of the effective data in the blob.
  uint16_t data_size;
  uint32_t reserved;
  uint64_t blob_id;
  uint64_t blob_next;
  uint8_t data[0];
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

// Reserve a blob. `blob_size` must be power of 2.
static void* reserve_blob(BLOB_SIZE blob_size) {
  uint32_t zero = 0;
  uint64_t* blob_id = bpf_map_lookup_elem(&_blob_index_, &zero);
  if (!blob_id) {
    // Cannot happen.
    return 0;
  }

  lw_blob *blob = 0;
  switch (blob_size) {
    case SIZE_256: {
      blob = bpf_ringbuf_reserve(&_blob_ringbuf_, BLOB_SIZE_256, 0);
      break;
    }
    case SIZE_512: {
      blob = bpf_ringbuf_reserve(&_blob_ringbuf_, BLOB_SIZE_512, 0);
      break;
    }
    case SIZE_1024: {
      blob = bpf_ringbuf_reserve(&_blob_ringbuf_, BLOB_SIZE_1024, 0);
      break;
    }
    default: {}
  }

  if (!blob) {
    return 0;
  }

  blob-> version = 0x01;
  blob->blob_size = blob_size;
  blob->data_size = 0;
  blob->blob_id = *blob_id;
  blob->blob_next = 0;

  *blob_id = *blob_id + 1;
  bpf_map_update_elem(&_blob_index_, &zero, blob_id, BPF_ANY);

  return blob;
}

static inline void submit_blob(void *blob) {
  bpf_printk("[DEBUG] str copied %s", ((lw_blob*)blob)->data);
  bpf_ringbuf_submit(blob, 0);
}

static inline void discard_blob(void *blob) {
  bpf_ringbuf_discard(blob, 0);
}

// `next_blob` reserves a new blob and links it to `blob`. The new blob has the same size of the given `blob`.
// `next_blob` submits the given `blob`.
static inline lw_blob *next_blob(lw_blob *blob) {
  if (!blob) {
    return 0;
  }

  lw_blob *next = reserve_blob(blob->blob_size);
  if (next) {
    blob->blob_next = next->blob_id;
  }

  submit_blob(blob);
  return next;
}

// `copy_str_to_blob` copies str to blobs. This function returns
// * 0 if it has succeeded;
// * -1 if it has failed;
//
// `blob_id` is the first blob submitted, even if the function has failed.
// If no blobs are submitted, `blob_id` is -1.
// `str_len` is the length of the str successfully copied (NULL not included).
//
// The last byte of all blobs submitted is NUL.
//
// Maximum blobs supported by this function is 16.
#define MAX_BLOBS 16
static inline int32_t copy_str_to_blob(const void *str, uint64_t *blob_id, long *str_len,  BLOB_SIZE blob_size) {
  int32_t rv = -1;

  if (!str || !blob_id || !str_len) {
    return rv;
  }

  long total_copied = 0;

  lw_blob * blob = reserve_blob(blob_size);
  for (uint16_t i = 0; i < MAX_BLOBS && blob; i++) {
    if (i == 0) {
      *blob_id = blob->blob_id;
    }

    uint16_t size = 0;
    switch(blob_size) {
      case SIZE_256: {
        size = BLOB_SIZE_256;
        break;
      }
      case SIZE_512: {
        size = BLOB_SIZE_512;
        break;
      }
      case SIZE_1024: {
        size = BLOB_SIZE_1024;
        break;
      }
    }

    if (size == 0) {
      break;
    }

    size -= sizeof(lw_blob);
    long len = bpf_probe_read_kernel_str(blob->data, size, str + total_copied);
    if (len < 0) {
      break;
    }

    total_copied += len - 1;
    blob->data_size = len;

    if (len < size) {
      rv = 0;
      break;
    }

    uint8_t last;
    bpf_probe_read_kernel(&last, 1, str + total_copied);
    // No more blobs needed.
    if (last == 0) {
      rv = 0;
      break;
    }

    // MAX_BLOBS allocated.
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