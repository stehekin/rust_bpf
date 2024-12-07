#ifndef _LW_TYPES_H_
#define _LW_TYPES_H_

//
// `types.h` defines the structures of data passing from the ebpf to the userspace.
//

#include "macros.h"
#include "int_types.h"
#include "vmlinux.h"

// Trailing NULL included.
#define MAX_FILENAME 128

typedef enum  {
  SIZE_256 = 0,
  SIZE_512 = 1,
  SIZE_1024 = 2,
} BLOB_SIZE;

typedef struct {
  u8 version;
  // Size of the blob_size. This is an enum.
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