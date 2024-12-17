#ifndef __LW_BLOB_H__
#define __LW_BLOB_H__

#include "common/int_types.h"
#include "common/types.h"
#include "common/maps.h"

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#define MAX_BLOBS 16

static inline u64 create_blob_id(u64 v) {
  u64 cpu_id = bpf_get_smp_processor_id();
  u64 result =  (v & 0x0000FFFFFFFFFFFF) | (cpu_id << 48);
  return result;
}

static void* reserve_blob(BLOB_SIZE blob_size) {
  u32 zero = 0;
  u64* blob_id = bpf_map_lookup_elem(&_blob_index_, &zero);
  if (!blob_id) {
    // Cannot happen.
    return 0;
  }

  // First blob_id is 1 (skipping 0);
  *blob_id += 1;

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



  blob->version = 0x01;
  blob->blob_size = blob_size;
  blob->data_size = 0;
  blob->blob_id = create_blob_id(*blob_id);
  blob->blob_next = 0;

  bpf_map_update_elem(&_blob_index_, &zero, blob_id, BPF_ANY);
  return blob;
}

static inline void submit_blob(lw_blob *blob) {
  bpf_ringbuf_submit(blob, 0);
}

static inline void discard_blob(lw_blob *blob) {
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

// `copy_data_to_blob` copies data to blobs. This function returns
// * 0 if it has succeeded;
// * -1 if it has failed;
//
// `blob_id` is the first blob submitted, even if the function has failed.
// If no blobs are submitted, `blob_id` is 0.
// `data_len` is the length of the data to be copied (NULL not included).
//
// Maximum blobs supported by this function is 16.
static s32 copy_data_to_blob(const void *src, const u64 data_len, u64 *blob_id, u8 kernel_space) {
  s32 rv = -1;

  if (!src || !blob_id || !data_len) {
    return rv;
  }

  long data_ptr = 0;
  BLOB_SIZE blob_size = BLOB_SIZE_256;

  if (data_len > BLOB_SIZE_512 - sizeof(lw_blob)) {
    blob_size = BLOB_SIZE_1024;
  } else if (data_len > BLOB_SIZE_256 - sizeof(lw_blob)) {
    blob_size = BLOB_SIZE_512;
  }

  *blob_id = 0;
  lw_blob * blob = reserve_blob(blob_size);
  blob_size -= sizeof(lw_blob);

  for (u16 i = 0; i < MAX_BLOBS && blob; i++) {
    if (i == 0) {
      *blob_id = blob->blob_id;
    }

    long result = 0;

    if (kernel_space) {
      result = bpf_probe_read_kernel(blob->data, blob_size, src + data_ptr);
    } else {
      result = bpf_probe_read_user(blob->data, blob_size, src + data_ptr);
    }
    if (result < 0) {
      if (i == 0) {
        *blob_id = 0;
      }
      break;
    }

    u64 copied = data_len - data_ptr;
    if (copied > blob_size) {
      copied = blob_size;
    }

    data_ptr += copied;
    blob->data_size = copied;

    if (data_ptr == data_len) {
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


#endif