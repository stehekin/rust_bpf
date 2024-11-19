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

#endif