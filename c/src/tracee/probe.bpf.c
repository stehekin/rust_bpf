#include <linux/bpf.h>
#include <linux/types.h>
#include <linux/magic.h>

#include <limits.h>
#include <stdint.h>

#include <bpf_core_read.h>
#include <bpf_endian.h>
#include <bpf_helpers.h>
#include <bpf_tracing.h>

#include "common/arch.h"
#include "common/blob.h"
#include "common/signals.h"
#include "common/types.h"
#include "common/vmlinux.h"

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

        init_task_context(&task_info->context, task, config->options);
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

    if (is_compat(task)) {
        // Translate 32bit syscalls to 64bit syscalls, so we can send to the correct handler
        u32 *id_64 = bpf_map_lookup_elem(&sys_32_to_64_map, &sys->id);
        if (id_64 == 0)
            return 0;

        sys->id = *id_64;
    }

    // exit, exit_group and rt_sigreturn syscalls don't return
    if (sys->id != SYSCALL_EXIT && sys->id != SYSCALL_EXIT_GROUP &&
            sys->id != SYSCALL_RT_SIGRETURN) {
        sys->ts = get_current_time_in_ns();
        task_info->syscall_traced = true;
    }

    // if id is irrelevant continue to next tail call
    bpf_tail_call(ctx, &sys_enter_submit_tail, sys->id);

    // call syscall handler, if exists
    bpf_tail_call(ctx, &sys_enter_tails, sys->id);
    return 0;
}