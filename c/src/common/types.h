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
} task_info_t;

typedef struct policies_config {
    // bitmap indicating which policies have the filter enabled
    u64 uid_filter_enabled;
    u64 pid_filter_enabled;
    u64 mnt_ns_filter_enabled;
    u64 pid_ns_filter_enabled;
    u64 uts_ns_filter_enabled;
    u64 comm_filter_enabled;
    u64 cgroup_id_filter_enabled;
    u64 cont_filter_enabled;
    u64 new_cont_filter_enabled;
    u64 new_pid_filter_enabled;
    u64 proc_tree_filter_enabled;
    u64 bin_path_filter_enabled;
    u64 follow_filter_enabled;
    // bitmap indicating whether to match a rule if the key is missing from its filter map
    u64 uid_filter_match_if_key_missing;
    u64 pid_filter_match_if_key_missing;
    u64 mnt_ns_filter_match_if_key_missing;
    u64 pid_ns_filter_match_if_key_missing;
    u64 uts_ns_filter_match_if_key_missing;
    u64 comm_filter_match_if_key_missing;
    u64 cgroup_id_filter_match_if_key_missing;
    u64 cont_filter_match_if_key_missing;
    u64 new_cont_filter_match_if_key_missing;
    u64 new_pid_filter_match_if_key_missing;
    u64 proc_tree_filter_match_if_key_missing;
    u64 bin_path_filter_match_if_key_missing;
    // bitmap with policies that have at least one filter enabled
    u64 enabled_policies;
    // global min max
    u64 uid_max;
    u64 uid_min;
    u64 pid_max;
    u64 pid_min;
} policies_config_t;

typedef struct file_id {
    dev_t device;
    unsigned long inode;
    u64 ctime;
} file_id_t;

typedef struct file_info {
    union {
        char pathname[MAX_CACHED_PATH_SIZE];
        char *pathname_p;
    };
    file_id_t id;
} file_info_t;

typedef struct binary {
    u32 mnt_id;
    char path[MAX_BIN_PATH_SIZE];
} binary_t;

typedef struct proc_info {
    bool new_proc;        // set if this process was started after tracee. Used with new_pid filter
    u64 follow_in_scopes; // set if this process was traced before. Used with the follow filter
    struct binary binary;
    u32 binary_no_mnt; // used in binary lookup when we don't care about mount ns. always 0.
    file_info_t interpreter;
} proc_info_t;

typedef struct config_entry {
    u32 tracee_pid;
    u32 options;
    u32 cgroup_v1_hid;
    u16 padding; // free for further use
    u16 policies_version;
    policies_config_t policies_config;
} config_entry_t;

typedef struct event_context {
    u64 ts; // timestamp
    task_context_t task;
    u32 eventid;
    s32 syscall; // syscall that triggered the event
    s64 retval;
    u32 stack_id;
    u16 processor_id; // ID of the processor that processed the event
    u16 policies_version;
    u64 matched_policies;
} event_context_t;

typedef struct event_config {
    u64 submit_for_policies;
    u64 param_types;
} event_config_t;

typedef struct args_buffer {
    u8 argnum;
    char args[ARGS_BUF_SIZE];
    u32 offset;
} args_buffer_t;

typedef struct event_data {
    event_context_t context;
    args_buffer_t args_buf;
    struct task_struct *task;
    event_config_t config;
    policies_config_t policies_config;
} event_data_t;

typedef struct program_data {
    config_entry_t *config;
    task_info_t *task_info;
    proc_info_t *proc_info;
    event_data_t *event;
    u32 scratch_idx;
    void *ctx;
} program_data_t;

enum bpf_log_level
{
    BPF_LOG_LVL_DEBUG = -1,
    BPF_LOG_LVL_INFO,
    BPF_LOG_LVL_WARN,
    BPF_LOG_LVL_ERROR,
};

enum bpf_log_id
{
    BPF_LOG_ID_UNSPEC = 0U, // enforce enum to u32

    // tracee functions
    BPF_LOG_ID_INIT_CONTEXT,

    // bpf helpers functions
    BPF_LOG_ID_MAP_LOOKUP_ELEM,
    BPF_LOG_ID_MAP_UPDATE_ELEM,
    BPF_LOG_ID_MAP_DELETE_ELEM,
    BPF_LOG_ID_GET_CURRENT_COMM,
    BPF_LOG_ID_TAIL_CALL,
    BPF_LOG_ID_MEM_READ,

    // hidden kernel module functions
    BPF_LOG_ID_HID_KER_MOD,
};

typedef struct bpf_log {
    s64 ret; // return value
    u32 cpu;
    u32 line;                        // line number
    char file[BPF_MAX_LOG_FILE_LEN]; // filename
} bpf_log_t;


typedef struct {
    enum bpf_log_id id; // type
    enum bpf_log_level level;
    u32 count;
    u32 padding;
    struct bpf_log log;
} bpf_log_output_t;

typedef union {
    bpf_log_output_t log_output;
    proc_info_t proc_info;
    task_info_t task_info;
} scratch_t;

#endif