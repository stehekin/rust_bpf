#ifndef __LW_TYPES_H__
#define __LW_TYPES_H__

//
// `types.h` defines the structures of data passing from the ebpf to the userspace.
//
#include "int_types.h"

// Trailing NULL included.
#define BLOBSTR_LEN 128
#define BLOB_SIZE 1024
#define BLOB_DATA_SIZE (BLOB_SIZE - sizeof(lw_blob_header))

typedef struct {
  // blob size = 1024
  u16 blob_size;
  // Size of the effective data in the blob.
  u16 effective_data_size;
  u32 _reserved;
  u64 blob_id;
  u64 blob_next;
} lw_blob_header;

typedef struct {
  lw_blob_header header;
  u8 data[BLOB_DATA_SIZE];
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
  u64 cgroup_id;
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
  u32 session_id;
  u32 login_uid;
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
  u32 _reserved;
  u64 submit_time_ns;
} lw_sigal_header;

typedef struct {
  lw_sigal_header header;
  lw_task body;
} lw_signal_task;

#endif
