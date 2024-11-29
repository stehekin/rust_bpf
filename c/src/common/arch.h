#ifndef __LW_ARCH_H__
#define __LW_ARCH_H__

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/vmlinux.h"

// TODO: support both ARM and x86.
#if defined(__TARGET_ARCH_x86)
  #define TS_COMPAT 0x0002
#elif defined(__TARGET_ARCH_arm64)
#endif

static inline bool is_x86_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return BPF_CORE_READ(task, thread_info.status) & TS_COMPAT;
#else
    return false;
#endif
}

static inline bool is_arm64_compat(struct task_struct *task)
{
#if defined(bpf_target_arm64)
    return BPF_CORE_READ(task, thread_info.flags) & _TIF_32BIT;
#else
    return false;
#endif
}

static inline bool is_compat(struct task_struct *task)
{
#if defined(bpf_target_x86)
    return is_x86_compat(task);
#elif defined(bpf_target_arm64)
    return is_arm64_compat(task);
#else
    return false;
#endif
}

#endif