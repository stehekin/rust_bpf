#include "common/int_types.h"
#include "common/vmlinux.h"

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

char _license[] SEC("license") = "GPL";

// https://github.com/torvalds/linux/blob/master/tools/testing/selftests/bpf/progs/cgroup_hierarchical_stats.c
SEC("iter.s/cgroup")
int BPF_PROG(cgroup_iter, struct bpf_iter_meta *meta, struct cgroup *cgrp) {
    if (!meta || !cgrp) {
        return 1;
    }
    struct seq_file *seq = meta->seq;
    u64 cg_id = BPF_CORE_READ(cgrp, kn, id);
    if (!cg_id) {
        return 1;
    }

    bpf_seq_write(seq, &cg_id, sizeof(u64));
    return 0;
}
