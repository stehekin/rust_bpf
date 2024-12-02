#ifndef _LW_MACROS_H_
#define _LW_MACROS_H_

#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)

// Trailing 0 included.
#define MAX_NAME_LEN 128
#define MAX_CACHED_PATH_SIZE MAX_NAME_LEN
#define MAX_BIN_PATH_SIZE MAX_NAME_LEN
#define ARGS_BUF_SIZE MAX_NAME_LEN
#define BPF_MAX_LOG_FILE_LEN MAX_NAME_LEN

#define BPF_LOOP_STOP 1
#define BPF_LOOP_CONTINUE 0

#define TASK_COMM_LEN 16

// Kernel thread flag.
#define PF_KTHREAD 0x00200000

#define OPT_EXEC_ENV              (1 << 0)
#define OPT_CAPTURE_FILES_WRITE   (1 << 1)
#define OPT_EXTRACT_DYN_CODE      (1 << 2)
#define OPT_CAPTURE_STACK_TRACES  (1 << 3)
#define OPT_CAPTURE_MODULES       (1 << 4)
#define OPT_CGROUP_V1             (1 << 5)
#define OPT_TRANSLATE_FD_FILEPATH (1 << 6)
#define OPT_CAPTURE_BPF           (1 << 7)
#define OPT_CAPTURE_FILES_READ    (1 << 8)
#define OPT_FORK_PROCTREE         (1 << 9)

#define MAX_FILTER_VERSION 64

enum event_id_e
{
    // Net events IDs
    NET_PACKET_BASE = 700,
    NET_PACKET_RAW,
    NET_PACKET_IP,
    NET_PACKET_TCP,
    NET_PACKET_UDP,
    NET_PACKET_ICMP,
    NET_PACKET_ICMPV6,
    NET_PACKET_DNS,
    NET_PACKET_HTTP,
    NET_CAPTURE_BASE,
    NET_FLOW_BASE,
    MAX_NET_EVENT_ID,
    // Common event IDs
    RAW_SYS_ENTER,
    RAW_SYS_EXIT,
    SCHED_PROCESS_FORK,
    SCHED_PROCESS_EXEC,
    SCHED_PROCESS_EXIT,
    SCHED_SWITCH,
    DO_EXIT,
    CAP_CAPABLE,
    VFS_WRITE,
    VFS_WRITEV,
    VFS_READ,
    VFS_READV,
    MEM_PROT_ALERT,
    COMMIT_CREDS,
    SWITCH_TASK_NS,
    MAGIC_WRITE,
    CGROUP_ATTACH_TASK,
    CGROUP_MKDIR,
    CGROUP_RMDIR,
    SECURITY_BPRM_CHECK,
    SECURITY_FILE_OPEN,
    SECURITY_INODE_UNLINK,
    SECURITY_SOCKET_CREATE,
    SECURITY_SOCKET_LISTEN,
    SECURITY_SOCKET_CONNECT,
    SECURITY_SOCKET_ACCEPT,
    SECURITY_SOCKET_BIND,
    SECURITY_SOCKET_SETSOCKOPT,
    SECURITY_SB_MOUNT,
    SECURITY_BPF,
    SECURITY_BPF_MAP,
    SECURITY_KERNEL_READ_FILE,
    SECURITY_INODE_MKNOD,
    SECURITY_POST_READ_FILE,
    SECURITY_INODE_SYMLINK,
    SECURITY_MMAP_FILE,
    SECURITY_FILE_MPROTECT,
    SOCKET_DUP,
    HIDDEN_INODES,
    __KERNEL_WRITE,
    PROC_CREATE,
    KPROBE_ATTACH,
    CALL_USERMODE_HELPER,
    DIRTY_PIPE_SPLICE,
    DEBUGFS_CREATE_FILE,
    SYSCALL_TABLE_CHECK,
    DEBUGFS_CREATE_DIR,
    DEVICE_ADD,
    REGISTER_CHRDEV,
    SHARED_OBJECT_LOADED,
    DO_INIT_MODULE,
    SOCKET_ACCEPT,
    LOAD_ELF_PHDRS,
    HOOKED_PROC_FOPS,
    PRINT_NET_SEQ_OPS,
    TASK_RENAME,
    SECURITY_INODE_RENAME,
    DO_SIGACTION,
    BPF_ATTACH,
    KALLSYMS_LOOKUP_NAME,
    DO_MMAP,
    PRINT_MEM_DUMP,
    VFS_UTIMES,
    DO_TRUNCATE,
    FILE_MODIFICATION,
    INOTIFY_WATCH,
    SECURITY_BPF_PROG,
    PROCESS_EXECUTE_FAILED,
    SECURITY_PATH_NOTIFY,
    SET_FS_PWD,
    HIDDEN_KERNEL_MODULE_SEEKER,
    MODULE_LOAD,
    MODULE_FREE,
    EXECUTE_FINISHED,
    PROCESS_EXECUTE_FAILED_INTERNAL,
    SECURITY_TASK_SETRLIMIT,
    SECURITY_SETTIME64,
    CHMOD_COMMON,
    MAX_EVENT_ID,
    NO_EVENT_SUBMIT,

    // Test events IDs
    EXEC_TEST = 8000,
    TEST_MISSING_KSYMBOLS,
    TEST_FAILED_ATTACH,
};

// Flags in each task's context
enum context_flags_e {
    CONTAINER_STARTED_FLAG = (1 << 0), // mark the task's container have started
    IS_COMPAT_FLAG = (1 << 1)          // is the task running in compatible mode
};

enum container_state_e {
    CONTAINER_UNKNOWN = 0, // mark that container state is unknown
    CONTAINER_EXISTED,     // container existed before tracee was started
    CONTAINER_CREATED,     // new cgroup path created
    CONTAINER_STARTED      // a process in the cgroup executed a new binary
};

#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif

#endif
