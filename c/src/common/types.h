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

#define MAX_FILENAME 128

typedef enum  {
  SIZE_256,
  SIZE_512,
  SIZE_1024,
} BLOB_SIZE;

typedef struct {
  uint8_t version;
  BLOB_SIZE blob_size;
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
  uint64_t start_boottime;
  uint32_t ppid;
  uint32_t rpid;
  // str_flag determines if filename and interp are blob ids or strings.
  uint64_t str_flag;
  uint8_t filename[MAX_FILENAME];
  uint8_t interp[MAX_FILENAME];
} lw_task;

/// Signal definitions.
typedef struct {
  uint16_t version;
  uint16_t type;
  uint32_t reserved;
} lw_signal_header;

typedef struct {
  lw_signal_header header;
  lw_creds creds;
  lw_task task;
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