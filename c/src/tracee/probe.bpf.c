#include "common/arch.h"
#include "common/macros.h"
#include "common/task.h"
#include "common/types.h"
#include "common/kconfig.h"

char _license[] SEC("license") = "GPL";

SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx) {
    struct task_struct *task = (struct task_struct *) bpf_get_current_task();

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = pid_tgid;
    task_info_t *task_info = bpf_map_lookup_elem(&task_info_map, &tid);
    if (unlikely(task_info == NULL)) {
        task_info = init_task_info(tid, 0);
        if (unlikely(task_info == NULL))
            return 0;

        int zero = 0;
        config_entry_t *config = bpf_map_lookup_elem(&config_map, &zero);
        if (unlikely(config == NULL))
            return 0;

        init_task_context(&task_info->context, task);
    }

    syscall_data_t *sys = &(task_info->syscall_data);
    sys->id = ctx->args[1];

    // See https://xcellerator.github.io/posts/linux_rootkits_02/ to understand
    // syscall wrapper in kernel 4.17+
    if (get_kconfig(ARCH_HAS_SYSCALL_WRAPPER)) {
        struct pt_regs *regs = (struct pt_regs *) ctx->args[0];

        if (is_x86_compat(task)) {
#if defined(bpf_target_x86)
            sys->args.args[0] = BPF_CORE_READ(regs, bx);
            sys->args.args[1] = BPF_CORE_READ(regs, cx);
            sys->args.args[2] = BPF_CORE_READ(regs, dx);
            sys->args.args[3] = BPF_CORE_READ(regs, si);
            sys->args.args[4] = BPF_CORE_READ(regs, di);
            sys->args.args[5] = BPF_CORE_READ(regs, bp);
#endif // bpf_target_x86
        } else {
            sys->args.args[0] = PT_REGS_PARM1_CORE_SYSCALL(regs);
            sys->args.args[1] = PT_REGS_PARM2_CORE_SYSCALL(regs);
            sys->args.args[2] = PT_REGS_PARM3_CORE_SYSCALL(regs);
            sys->args.args[3] = PT_REGS_PARM4_CORE_SYSCALL(regs);
            sys->args.args[4] = PT_REGS_PARM5_CORE_SYSCALL(regs);
            sys->args.args[5] = PT_REGS_PARM6_CORE_SYSCALL(regs);
        }
    } else {
        bpf_probe_read(sys->args.args, sizeof(6 * sizeof(u64)), (void *) ctx->args);
    }

    // exit, exit_group and rt_sigreturn syscalls don't return
    if (sys->id != SYSCALL_EXIT && sys->id != SYSCALL_EXIT_GROUP &&
        sys->id != SYSCALL_RT_SIGRETURN) {
        sys->ts = bpf_ktime_get_boot_ns();
        task_info->syscall_traced = true;
    }

    // // if id is irrelevant continue to next tail call
    // bpf_tail_call(ctx, &sys_enter_submit_tail, sys->id);

    // // call syscall handler, if exists
    // bpf_tail_call(ctx, &sys_enter_tails, sys->id);

    return 0;
}