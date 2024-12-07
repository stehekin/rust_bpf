#ifndef __LW_TYPES_H__
#define __LW_TYPES_H__

//
// `types.h` defines the structures of data passing from the ebpf to the userspace.
//
#include "int_types.h"

// Trailing NULL included.
#define MAX_FILENAME 128

typedef enum  {
  BLOB_SIZE_256 = 256,
  BLOB_SIZE_512 = 512,
  BLOB_SIZE_1024 = 1024,
  BLOB_SIZE_MAX = BLOB_SIZE_1024,
} BLOB_SIZE;

typedef struct {
  u8 version;
  // Size of the blob_size.
  u8 blob_size;
  // Size of the effective data in the blob.
  u16 data_size;
  u32 reserved;
  u64 blob_id;
  u64 blob_next;
  u8 data[0];
} lw_blob;

typedef struct {
  u32 uid;
  u32 gid;
  u32 euid;
  u32 egid;
} lw_creds;

typedef struct {
  u32 pid;
  u32 tgid;
  u64 start_boottime_ns;
  u32 ppid;
  u32 rpid;
  // `str_flag` determines if filename and interp are blob ids or strings.
  u64 str_flag;
  u8 filename[MAX_FILENAME];
  u8 interp[MAX_FILENAME];
  u8 pwd[MAX_FILENAME];
} lw_task;

#endif