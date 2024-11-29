#ifndef _LW_TASK_H_
#define _LW_TASK_H_

#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/types.h"
#include "common/vmlinux.h"

static struct task_struct *get_leader_task(struct task_struct *task) {
    return BPF_CORE_READ(task, group_leader);
}

static struct task_struct *get_parent_task(struct task_struct *task) {
    return BPF_CORE_READ(task, real_parent);
}

static u32 get_task_pid(struct task_struct *task) {
    return BPF_CORE_READ(task, pid);
}

static u32 get_task_ppid(struct task_struct *task) {
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

static u32 get_task_pid_vnr(struct task_struct *task) {
    unsigned int level = 0;
    struct pid *pid = BPF_CORE_READ(task, thread_pid);
    level = BPF_CORE_READ(pid, level);
    return BPF_CORE_READ(pid, numbers[level].nr);
}

static u32 get_task_ns_pid(struct task_struct *task) {
    return get_task_pid_vnr(task);
}

static u32 get_task_ns_tgid(struct task_struct *task) {
    struct task_struct *group_leader = BPF_CORE_READ(task, group_leader);
    return get_task_pid_vnr(group_leader);
}

static u32 get_task_pid_ns_id(struct task_struct *task) {
    unsigned int level = 0;
    struct pid * pid = BPF_CORE_READ(task, thread_pid);
    level = BPF_CORE_READ(pid, level);
    struct pid_namespace *ns = BPF_CORE_READ(pid, numbers[level].ns);
    return BPF_CORE_READ(ns, ns.inum);
}


static u32 get_mnt_ns_id(struct nsproxy *ns) {
    return BPF_CORE_READ(ns, mnt_ns, ns.inum);
}

static u32 get_task_mnt_ns_id(struct task_struct *task) {
    return get_mnt_ns_id(BPF_CORE_READ(task, nsproxy));
}

static u32 get_pid_ns_for_children_id(struct nsproxy *ns) {
    return BPF_CORE_READ(ns, pid_ns_for_children, ns.inum);
}

static u32 get_uts_ns_id(struct nsproxy *ns) {
    return BPF_CORE_READ(ns, uts_ns, ns.inum);
}

static u32 get_ipc_ns_id(struct nsproxy *ns) {
    return BPF_CORE_READ(ns, ipc_ns, ns.inum);
}

static u32 get_net_ns_id(struct nsproxy *ns) {
    return BPF_CORE_READ(ns, net_ns, ns.inum);
}

static u32 get_cgroup_ns_id(struct nsproxy *ns) {
    return BPF_CORE_READ(ns, cgroup_ns, ns.inum);
}

static u64 get_task_start_time(struct task_struct *task) {
    // Only use the boot time member if we can use boot time for current time
    if (bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_ktime_get_boot_ns)) {
        // real_start_time was renamed to start_boottime in kernel 5.5, so most likely
        // it will be available as the bpf_ktime_get_boot_ns is available since kernel 5.8.
        // The only case it won't be available is if it was backported to an older kernel.
        if (bpf_core_field_exists(struct task_struct, start_boottime))
            return BPF_CORE_READ(task, start_boottime);
        return BPF_CORE_READ(task, real_start_time);
    }
    return BPF_CORE_READ(task, start_time);
}

static char *get_task_uts_name(struct task_struct *task) {
    struct nsproxy *np = BPF_CORE_READ(task, nsproxy);
    struct uts_namespace *uts_ns = BPF_CORE_READ(np, uts_ns);
    return BPF_CORE_READ(uts_ns, name.nodename);
}

static u32 init_task_context(task_context_t *tsk_ctx, struct task_struct *task) {
    // NOTE: parent process is always a real process, not a potential thread group leader.
    struct task_struct *leader = get_leader_task(task);
    struct task_struct *parent_process = get_leader_task(get_parent_task(leader));

    // Task Info on Host
    tsk_ctx->host_ppid = get_task_pid(parent_process); // always a real process (not a light-weight process (lwp))
    // Namespaces Info
    tsk_ctx->tid = get_task_ns_pid(task);
    tsk_ctx->pid = get_task_ns_tgid(task);

    u32 task_pidns_id = get_task_pid_ns_id(task);
    u32 parent_process_pidns_id = get_task_pid_ns_id(parent_process);

    if (task_pidns_id == parent_process_pidns_id)
        tsk_ctx->ppid = get_task_ns_pid(parent_process); // e.g: pid 1 will have nsppid 0

    tsk_ctx->pid_id = task_pidns_id;
    tsk_ctx->mnt_id = get_task_mnt_ns_id(task);
    // User Info
    tsk_ctx->uid = bpf_get_current_uid_gid();
    // Times
    tsk_ctx->start_time = get_task_start_time(task);
    tsk_ctx->leader_start_time = get_task_start_time(leader);
    tsk_ctx->parent_start_time = get_task_start_time(parent_process);

    // Program name
    bpf_get_current_comm(&tsk_ctx->comm, sizeof(tsk_ctx->comm));

    // UTS Name
    char *uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_kernel_str(&tsk_ctx->uts_name, TASK_COMM_LEN, uts_name);

    return 0;
}


#endif