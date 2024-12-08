#ifndef __LW_TYPES_H__
#define __LW_TYPES_H__

//
// `types.h` defines the structures of data passing from the ebpf to the userspace.
//
#include "int_types.h"

// Trailing NULL included.
#define BLOBSTR_LEN 128

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
  u32 _reserved;
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
  u32 pid_vnr;
  u32 pid_ns;
  u32 session_id;
} lw_proc;

typedef union {
  u8 str[BLOBSTR_LEN];
  struct {
    u64 blob_id;
    u64 flag;
  } blob;
} lw_blobstr;

typedef struct {
  lw_blobstr filename;
  lw_blobstr interp;
  u64 env;
} lw_exec;

typedef struct {
  lw_creds creds;
  lw_proc pid;
  lw_exec exec;
} lw_task;

#endif