#ifndef __LW_STR_H__
#define __LW_STR_H__

#include "common/blob.h"
#include "common/types.h"

static long str_copy_loop_func(u32 i, blob_loop_context *ctx) {
    lw_blob *blob = reserve_blob_with_id(ctx->blob_id);

    if (!blob) {
        return BLOB_LOOP_BREAK;
    }

    long len = 0;
    if (ctx->is_kernel) {
      len = bpf_probe_read_kernel_str(blob->data, BLOB_DATA_SIZE, ctx->src + ctx->data_ptr);
    } else {
      len = bpf_probe_read_user_str(blob->data, BLOB_DATA_SIZE, ctx->src + ctx->data_ptr);
    }

    if (len < 0) {
        discard_blob(blob);
        return BLOB_LOOP_BREAK;
    }

    // Don't count the trailing NIL.
    ctx->data_ptr += len - 1;
    blob->header.effective_data_size = len - 1;

    if (len < BLOB_DATA_SIZE || len == 1) {
        submit_blob(blob);
      ctx->return_value = 0;
      return BLOB_LOOP_BREAK;
    }

    ctx->blob_id = i < MAX_BLOBS - 1 ? next_blob_id() : 0;
    blob->header.blob_next = ctx->blob_id;
    submit_blob(blob);
    return BLOB_LOOP_CONTINUE;
}

// `copy_str_to_blob` copies str to blobs. This function returns
// * 0 if it has succeeded and `blob_id` is the first blob submitted;
// * -1 if it has failed;
//
// Notes:
// * `str_len` is the length of the str successfully copied (NULL not included). `str_len` can be null if the length is not needed.
// * The last byte of all blobs submitted is NUL.
// * Maximum blobs supported by this function is MAX_BLOBS.
static s32 copy_str_to_blob(const void *str, u64 *blob_id, u64 *str_len, bool is_kernel) {
  if (!str || !blob_id) {
    return -1;
  }

  *blob_id = next_blob_id();
  long total_copied = 0;

  blob_loop_context ctx  = {
      .src = (void *)str,
      .data_ptr = 0,
      .blob_id = *blob_id,
      .is_kernel = is_kernel,
      .return_value = -1,
  };

  bpf_loop(MAX_BLOBS, str_copy_loop_func, &ctx, 0);
  return ctx.return_value;
}

// `copy_str` copies str to the `dest`. This function returns
// * 0 if it has succeeded and all bytes in the `str` are copied (NUL included);
// * -1 if it has failed;
// * 1 if it has succeeded but not all bytes in the `str` has copied;
//
// `str_len` is the length of the str successfully copied (NUL included). `str_len` can be null if the length is not needed.
static inline s32 copy_str(u8 *dest, u16 size, const void *str, long *str_len, bool kernel) {
  if (!dest || !size || !str) {
    return -1;
  }

  long len = 0;
  if (kernel) {
    len = bpf_probe_read_kernel_str(dest, size, str);
  } else {
    len = bpf_probe_read_user_str(dest, size, str);
  }
  if (str_len) {
    *str_len = len;
  }

  if (len < 0) {
    return -1;
  } else if (len < size) {
    return 0;
  }

  // len == size
  u8 last;
  if (kernel) {
    bpf_probe_read_kernel(&last, 1, str + len - 1);
  } else {
    bpf_probe_read_user(&last, 1, str + len - 1);
  }
  if (last == 0) {
    return 0;
  } else {
    return 1;
  }
}

#endif
