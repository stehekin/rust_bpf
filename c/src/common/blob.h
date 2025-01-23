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
#define BLOB_LOOP_CONTINUE 0
#define BLOB_LOOP_BREAK 1

typedef struct {
    u64 data_len;
    u64 data_ptr;
    u64 *blob_id;
    void *src;
    bool is_kernel;
    lw_blob *blob;
    s32 rv;
} blob_loop_context;

static inline u64 create_blob_id(u64 v) {
  u64 cpu_id = bpf_get_smp_processor_id();
  u64 result =  (v & 0x0000FFFFFFFFFFFF) | (cpu_id << 48);
  return result;
}

static lw_blob* reserve_blob() {
  u32 zero = 0;
  u64* blob_id = bpf_map_lookup_elem(&_blob_index_, &zero);
  if (!blob_id) {
    // Cannot happen.
    return 0;
  }

  // First blob_id is 1 (skipping 0);
  *blob_id += 1;

  lw_blob *blob = bpf_ringbuf_reserve(&_blob_ringbuf_, BLOB_SIZE, 0);
  if (!blob) {
    return 0;
  }

  blob->header.blob_size = BLOB_SIZE;
  blob->header.effective_data_size = 0;
  blob->header.blob_id = create_blob_id(*blob_id);
  blob->header.blob_next = 0;

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

  lw_blob *next = reserve_blob();
  if (next) {
    blob->header.blob_next = next->header.blob_id;
  }

  submit_blob(blob);
  return next;
}

static long blob_loop_func(u32 i, blob_loop_context *ctx) {
    if (!ctx->blob) {
        return BLOB_LOOP_BREAK;
    }

    if (i == 0) {
      *(ctx->blob_id) = ctx->blob->header.blob_id;
    }

    u64 to_copy = ctx->data_len - ctx->data_ptr;
    if (to_copy > BLOB_DATA_SIZE) {
      to_copy = BLOB_DATA_SIZE;
    }

    long result = 0;

    if (ctx->is_kernel) {
      result = bpf_probe_read_kernel(ctx->blob->data, to_copy, ctx->src + ctx->data_ptr);
    } else {
      result = bpf_probe_read_user(ctx->blob->data, to_copy, ctx->src + ctx->data_ptr);
    }

    if (result < 0) {
      if (i == 0) {
        *(ctx->blob_id) = 0;
      }
      return BLOB_LOOP_BREAK;
    }

    ctx->data_ptr += to_copy;
    ctx->blob->header.effective_data_size = to_copy;

    if (ctx->data_ptr == ctx->data_len) {
      ctx->rv = 0;
      return BLOB_LOOP_BREAK;
    }

    // MAX_BLOBS allocated.
    if (i == MAX_BLOBS - 1) {
      submit_blob(ctx->blob);
      ctx->blob = 0;
      return BLOB_LOOP_BREAK;
    }

    ctx->blob = next_blob(ctx->blob);
    return BLOB_LOOP_CONTINUE;
}

// `copy_data_to_blob` copies data to blobs. This function returns
// * 0 if it has succeeded;
// * -1 if it has failed;
//
// `blob_id` is the first blob submitted, even if the function has failed.
// If no blobs are submitted, `blob_id` is 0.
// `data_len` is the length of the data to be copied.
//
// Maximum blobs supported by this function is MAX_BLOBS.
static s32 copy_data_to_blob(const void *src, const u64 data_len, u64 *blob_id, bool is_kernel) {
  if (!src || !blob_id || !data_len) {
    return -1;
  }

  u32 key = 0;
  *blob_id = 0;

  blob_loop_context ctx  = {
      .src = (void *)src,
      .data_len = data_len,
      .blob_id = blob_id,
      .is_kernel = is_kernel,
      .rv = -1,
      .data_ptr = 0,
      .blob = 0,
  };

  bpf_loop(MAX_BLOBS, blob_loop_func, &ctx, 0);

  if (ctx.blob) {
    if (ctx.rv == 0) {
      submit_blob(ctx.blob);
    } else {
      discard_blob(ctx.blob);
    }
  }

  return ctx.rv;
}

#endif
