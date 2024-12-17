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
} BLOB_SIZE;

typedef struct {
  u8 version;
  u8 reserved;
  // blob size.
  u16 blob_size;
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
  u32 tgid;
  u32 pid_ns;
  u32 pid_vnr;
} lw_pid;

typedef union {
  u8 str[BLOBSTR_LEN];
  struct {
    // blob_id is only effective when flag is 0.
    u64 flag;
    u64 blob_id;
  } blob;
} lw_blobstr;

typedef struct {
  lw_blobstr filename;
  lw_blobstr interp;
  u64 args;
  u64 env;
} lw_exec;

typedef struct {
  u32 pid;
  u32 tgid;
  u64 boot_ns;
} lw_parent;

typedef struct {
  lw_creds creds;
  lw_pid pid;
  lw_parent parent;
  lw_exec exec;
  u64 boot_ns;
} lw_task;

// signals sent to user space.

typedef enum {
  LW_SIGNAL_TASK = 1,
} lw_signal_type;

typedef struct {
  u8 version;
  u8 signal_type;
  u16 cpu_id;
  u32 reserved;
  u64 submit_time_ns;
} lw_sigal_header;

typedef struct {
  lw_sigal_header header;
  lw_task body;
} lw_signal_task;

#endif