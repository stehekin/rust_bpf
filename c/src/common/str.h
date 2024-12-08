#ifndef __LW_STR_H__
#define __LW_STR_H__

#include "bpf_helpers.h"
#include "common/blob.h"

// `copy_str_to_blob` copies str to blobs. This function returns
// * 0 if it has succeeded and `blob_id` is the first blob submitted;
// * -1 if it has failed;
//
// Notes:
// * `str_len` is the length of the str successfully copied (NULL not included). `str_len` can be null if the length is not needed.
// * The last byte of all blobs submitted is NUL.
// * Maximum blobs supported by this function is 16.
static s32 copy_str_to_blob(const void *str, u64 *blob_id, u64 *str_len,  BLOB_SIZE blob_size, u8 kernel_space) {
  s32 rv = -1;

  if (!str || !blob_id || !blob_size) {
    return rv;
  }

  *blob_id = 0;
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
      if (str_len) {
        *str_len = total_copied;
      }
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
// `str_len` is the length of the str successfully copied (NUL included). `str_len` can be null if the length is not needed.
static inline s32 copy_str(u8 *dest, u16 size, const void *str, long *str_len, bool kernel) {
  if (!dest || !size || !str) {
    return -1;
  }

  long len = 0;
  if (kernel) {
    bpf_probe_read_kernel_str(dest, size, str);
  } else {
    bpf_probe_read_user_str(dest, size, str);
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
