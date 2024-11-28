#ifndef _LW_TYPES_H_
#define _LW_TYPES_H_

//
// `types.h` defines the structures of data passing from the ebpf to the userspace.
//

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include "common/macros.h"

typedef enum {
  false = 0,
  true = 1
} bool;


// Trailing NULL included.
#define MAX_FILENAME 128

typedef enum  {
  SIZE_256 = 0,
  SIZE_512 = 1,
  SIZE_1024 = 2,
} BLOB_SIZE;

typedef struct {
  uint8_t version;
  // Size of the blob_size. This is an enum.
  uint8_t blob_size;
  // Size of the effective data in the blob.
  uint16_t data_size;
  uint32_t reserved;
  uint64_t blob_id;
  uint64_t blob_next;
  uint8_t data[0];
} lw_blob;

typedef struct {
  uint32_t uid;
  uint32_t gid;
  uint32_t euid;
  uint32_t egid;
} lw_creds;

typedef struct {
  uint32_t pid;
  uint32_t tgid;
  uint64_t start_boottime_ns;
  uint32_t ppid;
  uint32_t rpid;
  // `str_flag` determines if filename and interp are blob ids or strings.
  uint64_t str_flag;
  uint8_t filename[MAX_FILENAME];
  uint8_t interp[MAX_FILENAME];
  uint8_t pwd[MAX_FILENAME];
} lw_task;

//------------------------------------
//     Tracee Definitions Below
//------------------------------------

typedef struct task_context {
    uint64_t start_time;               // task's start time
    uint64_t cgroup_id;                // control group ID
    uint32_t pid;                      // PID as in the userspace term
    uint32_t tid;                      // TID as in the userspace term
    uint32_t ppid;                     // Parent PID as in the userspace term
    uint32_t host_pid;                 // PID in host pid namespace
    uint32_t host_tid;                 // TID in host pid namespace
    uint32_t host_ppid;                // Parent PID in host pid namespace
    uint32_t uid;                      // task's effective UID
    uint32_t mnt_id;                   // task's mount namespace ID
    uint32_t pid_id;                   // task's pid namespace ID
    char comm[TASK_COMM_LEN];     // task's comm
    char uts_name[TASK_COMM_LEN]; // task's uts name
    uint32_t flags;                    // task's status flags (see context_flags_e)
    uint64_t leader_start_time;        // task leader's monotonic start time
    uint64_t parent_start_time;        // parent process task leader's monotonic start time
} task_context_t;

typedef struct {
    unsigned long args[6];
} args_t;

typedef struct {
    uint32_t id;           // Current syscall id
    args_t args;       // Syscall arguments
    unsigned long ts;  // Timestamp of syscall entry
    unsigned long ret; // Syscall ret val. May be used by syscall exit tail calls.
} syscall_data_t;

typedef struct {
    task_context_t context;
    syscall_data_t syscall_data;
    bool syscall_traced; // indicates that syscall_data is valid
    uint8_t container_state;  // the state of the container the task resides in
    bool initialized; // this task_info_t has been initialized
} task_info_t;

#endif