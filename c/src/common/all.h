#ifndef _NENP_COMMON_BPF_H_
#define _NENP_COMMON_BPF_H_

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "vmlinux.h"

char _license[] SEC("license") = "GPL";

#endif