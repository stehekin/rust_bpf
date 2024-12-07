#ifndef _LW_BLOB_H_
#define _LW_BLOB_H_

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "int_types.h"
#include "types.h"

#define BLOB_MAP_ENTRIES 1024 * BLOB_SIZE_MAX

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


static inline u64 create_blob_id(u64 v) {
  u64 cpu_id = bpf_get_smp_processor_id();
  u64 result =  (v & 0x0000FFFFFFFFFFFF) | (cpu_id << 48);
  return result;
}

// static inline BLOB_SIZE to_blob_size(long data_len, u16 *size) {
//     BLOB_SIZE blob_size = SIZE_256;
//     *size = 256;

//     if (data_len > BLOB_SIZE_512 - sizeof(lw_blob)) {
//       blob_size = SIZE_1024;
//       *size = 1024;
//     } else if (data_len > BLOB_SIZE_256 - sizeof(lw_blob)) {
//       blob_size = SIZE_512;
//       *size = 512;
//     }

//     return blob_size;
// }

// static inline u16 from_blob_size(BLOB_SIZE blob_size) {
//     u16 size = 0;
//     switch(blob_size) {
//       case SIZE_256: {
//         size = BLOB_SIZE_256;
//         break;
//       }
//       case SIZE_512: {
//         size = BLOB_SIZE_512;
//         break;
//       }
//       case SIZE_1024: {
//         size = BLOB_SIZE_1024;
//         break;
//       }
//     }
//     return size;
// }

static void* reserve_blob(BLOB_SIZE blob_size) {
  u32 zero = 0;
  u64* blob_id = bpf_map_lookup_elem(&_blob_index_, &zero);
  if (!blob_id) {
    // Cannot happen.
    return 0;
  }

  lw_blob *blob = 0;
  switch (blob_size) {
    case BLOB_SIZE_256: {
      blob = bpf_ringbuf_reserve(&_blob_ringbuf_, BLOB_SIZE_256, 0);
      break;
    }
    case BLOB_SIZE_512: {
      blob = bpf_ringbuf_reserve(&_blob_ringbuf_, BLOB_SIZE_512, 0);
      break;
    }
    case BLOB_SIZE_1024: {
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
  blob->blob_id = create_blob_id(*blob_id);
  blob->blob_next = 0;

  *blob_id = *blob_id + 1;

  bpf_map_update_elem(&_blob_index_, &zero, blob_id, BPF_ANY);

  return blob;
}

static inline void submit_blob(void *blob) {
  // bpf_printk("[DEBUG] str copied %s", ((lw_blob*)blob)->data);
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
static s32 copy_str_to_blob(const void *str, u64 *blob_id, u64 *str_len,  BLOB_SIZE blob_size, u8 kernel_space) {
  s32 rv = -1;

  if (!str || !blob_id || !str_len || !blob_size) {
    return rv;
  }

  long total_copied = 0;

  lw_blob * blob = reserve_blob(blob_size);
  for (u16 i = 0; i < MAX_BLOBS && blob; i++) {
    if (i == 0) {
      *blob_id = blob->blob_id;
    }

    blob_size -= sizeof(lw_blob);
    long len = 0;
    if (kernel_space) {
      len = bpf_probe_read_kernel_str(blob->data, blob_size, str + total_copied);
    } else {
      len = bpf_probe_read_user_str(blob->data, blob_size, str + total_copied);
    }
    if (len < 0) {
      break;
    }

    bpf_printk("[DEBUG] %s", blob->data);

    // Don't count the trailing NIL.
    total_copied += len - 1;
    blob->data_size = len - 1;

    if (len < blob_size) {
      rv = 0;
      break;
    }

    u8 last;
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

// `copy_data_to_blob` copies data to blobs. This function returns
// * 0 if it has succeeded;
// * -1 if it has failed;
//
// `blob_id` is the first blob submitted, even if the function has failed.
// If no blobs are submitted, `blob_id` is -1.
// `data_len` is the length of the data to be copied (NULL not included).
//
// Maximum blobs supported by this function is 16.
static s32 copy_data_to_blob(const void *src, u64 data_len, u64 *blob_id, u8 kernel_space) {
  s32 rv = -1;

  if (!src || !blob_id || !data_len) {
    return rv;
  }

  long total_copied = 0;
  BLOB_SIZE blob_size = BLOB_SIZE_256;

  if (data_len > BLOB_SIZE_512 - sizeof(lw_blob)) {
    blob_size = BLOB_SIZE_1024;
  } else if (data_len > BLOB_SIZE_256 - sizeof(lw_blob)) {
    blob_size = BLOB_SIZE_512;
  }

  lw_blob * blob = reserve_blob(blob_size);
  blob_size -= sizeof(lw_blob);

  for (u16 i = 0; i < MAX_BLOBS && blob; i++) {
    if (i == 0) {
      *blob_id = blob->blob_id;
    }

    long len = 0;
    if (kernel_space) {
      len = bpf_probe_read_kernel(blob->data, blob_size, src + total_copied);
    } else {
      len = bpf_probe_read_user(blob->data, blob_size, src + total_copied);
    }
    if (len < 0) {
      break;
    }

    total_copied += len;
    blob->data_size = len;
    data_len -= len;

    if (!data_len) {
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
// `str_len` is the length of the str successfully copied (NUL included).
static inline s32 copy_str(u8 *dest, u16 size, const void *str, long *str_len) {
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
  u8 last;
  bpf_probe_read_kernel(&last, 1, str + len - 1);
  if (last == 0) {
    return 0;
  } else {
    return 1;
  }
}

#endif