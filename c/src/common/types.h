#ifndef _LW_TYPES_H_
#define _LW_TYPES_H_

//
// `types.h` defines the structures of data passing from the ebpf to the userspace.
//

#include "common/macros.h"
#include "common/int_types.h"

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

//------------------------------------
//     Tracee Definitions Below
//------------------------------------

typedef struct task_context {
    u64 start_time;               // task's start time
    u64 cgroup_id;                // control group ID
    u32 pid;                      // PID as in the userspace term
    u32 tid;                      // TID as in the userspace term
    u32 ppid;                     // Parent PID as in the userspace term
    u32 host_pid;                 // PID in host pid namespace
    u32 host_tid;                 // TID in host pid namespace
    u32 host_ppid;                // Parent PID in host pid namespace
    u32 uid;                      // task's effective UID
    u32 mnt_id;                   // task's mount namespace ID
    u32 pid_id;                   // task's pid namespace ID
    char comm[TASK_COMM_LEN];     // task's comm
    char uts_name[TASK_COMM_LEN]; // task's uts name
    u32 flags;                    // task's status flags (see context_flags_e)
    u64 leader_start_time;        // task leader's monotonic start time
    u64 parent_start_time;        // parent process task leader's monotonic start time
} task_context_t;

typedef struct {
    unsigned long args[6];
} args_t;

typedef struct {
    u32 id;           // Current syscall id
    args_t args;       // Syscall arguments
    unsigned long ts;  // Timestamp of syscall entry
    unsigned long ret; // Syscall ret val. May be used by syscall exit tail calls.
} syscall_data_t;

typedef struct {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced; // indicates that syscall_data is valid
    u8 container_state;  // the state of the container the task resides in
    bool initialized; // this task_info_t has been initialized
} task_info_t;

#endif