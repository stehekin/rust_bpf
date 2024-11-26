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
//     Signal Definitions Below
//------------------------------------

typedef enum {
  SIGNAL_TASK = 0x01,
} lw_signal_type;

// cpu_id + time_ns is the key of a signal.
typedef struct {
  uint8_t version;
  uint8_t type;
  // Id of the cpu emitted the event.
  uint16_t cpu_id;
  uint16_t reserved;
  uint64_t signal_time_ns;
} lw_signal_header;

typedef struct {
  lw_signal_header header;
  lw_creds creds;
  lw_task task;
  uint64_t start_boottime_ns;
} lw_signal_task;

// static int parse_task(struct task_struct *src, lw_task *target) {
//   if (!src || !target) {
//     return 0;
//   }

//   target->pid = BPF_CORE_READ(src, pid);
//   target->tgid = BPF_CORE_READ(src, tgid);
//   target->start_boottime = BPF_CORE_READ(src, start_boottime);

//   return 0;
// }

#endif