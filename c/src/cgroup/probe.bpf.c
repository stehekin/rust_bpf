// #include "common/int_types.h"
// #include "common/signals.h"
// #include "common/str.h"
// #include "common/types.h"
// #include "common/vmlinux.h"
// #include "common/task.h"
// #include "common/blob.h"
// #include "common/maps.h"

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// extern void cgroup_rstat_flush(struct cgroup *cgrp) __ksym;

SEC("iter.s/cgroup")
int BPF_PROG(dumper, struct cgroup * cgroup) {
    return 0;
}
