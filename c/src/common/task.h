#ifndef _LW_TASK_H_
#define _LW_TASK_H_


#include "common/macros.h"
#include "common/vmlinux.h"
#include "maps.h"
#include "arch.h"
#include <bpf_core_read.h>
#include <bpf_helpers.h>

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

    if (is_compat(task)) {
      tsk_ctx->flags |= IS_COMPAT_FLAG;
    }

    // Program name
    bpf_get_current_comm(&tsk_ctx->comm, sizeof(tsk_ctx->comm));

    // UTS Name
    char *uts_name = get_task_uts_name(task);
    if (uts_name)
        bpf_probe_read_kernel_str(&tsk_ctx->uts_name, TASK_COMM_LEN, uts_name);

    return 0;
}

static inline int get_task_flags(struct task_struct *task) {
    return BPF_CORE_READ(task, flags);
}

static inline int get_syscall_id_from_regs(struct pt_regs *regs)
{
#if defined(bpf_target_x86)
    int id = BPF_CORE_READ(regs, orig_ax);
#elif defined(bpf_target_arm64)
    int id = BPF_CORE_READ(regs, syscallno);
#endif
    return id;
}

static int get_current_task_syscall_id(void) {
  // There is no originated syscall in kernel thread context
  struct task_struct *curr = (struct task_struct *) bpf_get_current_task_btf();
  if (get_task_flags(curr) & PF_KTHREAD) {
      return NO_SYSCALL;
  }

  struct pt_regs *regs = (struct pt_regs *) bpf_task_pt_regs(curr);
  return get_syscall_id_from_regs(regs);
}

static void init_proc_info_scratch(u32 pid, scratch_t *scratch) {
    __builtin_memset(&scratch->proc_info, 0, sizeof(proc_info_t));
    bpf_map_update_elem(&proc_info_map, &pid, &scratch->proc_info, BPF_NOEXIST);
}

static proc_info_t *init_proc_info(u32 pid, u32 scratch_idx) {
    scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_idx);
    if (unlikely(scratch == NULL))
        return NULL;

    init_proc_info_scratch(pid, scratch);

    return bpf_map_lookup_elem(&proc_info_map, &pid);
}

static void init_task_info_scratch(u32 tid, scratch_t *scratch) {
    __builtin_memset(&scratch->task_info, 0, sizeof(task_info_t));
    bpf_map_update_elem(&task_info_map, &tid, &scratch->task_info, BPF_NOEXIST);
}

static task_info_t *init_task_info(u32 tid, u32 scratch_idx) {
    scratch_t *scratch = bpf_map_lookup_elem(&scratch_map, &scratch_idx);
    if (unlikely(scratch == NULL))
        return NULL;

    init_task_info_scratch(tid, scratch);

    return bpf_map_lookup_elem(&task_info_map, &tid);
}

static event_config_t *get_event_config(u32 event_id, u16 policies_version) {
    // TODO: we can remove this extra lookup by moving to per event rules_version
    void *inner_events_map = bpf_map_lookup_elem(&events_map_version, &policies_version);
    if (inner_events_map == NULL)
        return NULL;

    return bpf_map_lookup_elem(inner_events_map, &event_id);
}

static int init_program_data(program_data_t *p, void *ctx, u32 event_id) {
    int zero = 0;

    p->ctx = ctx;

    if (p->event == NULL) {
        p->event = bpf_map_lookup_elem(&event_data_map, &zero);
        if (unlikely(p->event == NULL))
            return 0;
    }

    p->config = bpf_map_lookup_elem(&config_map, &zero);
    if (unlikely(p->config == NULL))
        return 0;

    p->event->args_buf.offset = 0;
    p->event->args_buf.argnum = 0;
    p->event->task = (struct task_struct *)bpf_get_current_task_btf();

    __builtin_memset(&p->event->context.task, 0, sizeof(p->event->context.task));

    // Get the minimal context required at this stage.
    // Any other context will be initialized only if event is submitted.
    u64 id = bpf_get_current_pid_tgid();
    // Task pid.
    p->event->context.task.host_tid = id;
    // Task tgid.
    p->event->context.task.host_pid = id >> 32;
    p->event->context.eventid = event_id;
    p->event->context.ts = bpf_ktime_get_boot_ns();
    p->event->context.processor_id = (u16) bpf_get_smp_processor_id();
    p->event->context.syscall = get_current_task_syscall_id();

    u32 host_pid = p->event->context.task.host_pid;
    p->proc_info = bpf_map_lookup_elem(&proc_info_map, &host_pid);
    if (unlikely(p->proc_info == NULL)) {
        p->proc_info = init_proc_info(host_pid, p->scratch_idx);
        if (unlikely(p->proc_info == NULL))
            return 0;
    }

    u32 host_tid = p->event->context.task.host_tid;
    p->task_info = bpf_map_lookup_elem(&task_info_map, &host_tid);
    if (unlikely(p->task_info == NULL)) {
        p->task_info = init_task_info(host_tid, p->scratch_idx);
        if (unlikely(p->task_info == NULL))
            return 0;

        init_task_context(&p->task_info->context, p->event->task);
    }

    // Only cgroup v2 is supported.
    p->event->context.task.cgroup_id = bpf_get_current_cgroup_id();
    p->task_info->context.cgroup_id = p->event->context.task.cgroup_id;

    u32 cgroup_id_lsb = p->event->context.task.cgroup_id;
    u8 *state = bpf_map_lookup_elem(&containers_map, &cgroup_id_lsb);
    if (state != NULL) {
        p->task_info->container_state = *state;
        switch (*state) {
            case CONTAINER_STARTED:
            case CONTAINER_EXISTED:
                p->event->context.task.flags |= CONTAINER_STARTED_FLAG;
        }
    }

    if (unlikely(p->event->context.policies_version != p->config->policies_version)) {
        // copy policies_config to event data
        long ret = bpf_probe_read_kernel(
            &p->event->policies_config, sizeof(policies_config_t), &p->config->policies_config);
        if (unlikely(ret != 0))
            return 0;

        p->event->context.policies_version = p->config->policies_version;
    }

    // default to match all policies until an event is selected
    p->event->config.submit_for_policies = ~0ULL;

    if (event_id != NO_EVENT_SUBMIT) {
        p->event->config.submit_for_policies = 0;
        event_config_t *event_config = get_event_config(event_id, p->event->context.policies_version);
        if (event_config != NULL) {
            p->event->config.param_types = event_config->param_types;
            p->event->config.submit_for_policies = event_config->submit_for_policies;
        }
    }

    // initialize matched_policies to the policies that actually requested this event
    p->event->context.matched_policies = p->event->config.submit_for_policies;

    return 1;
}
#endif