#ifndef __LW_MACROS_H__
#define __LW_MACROS_H__

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

#ifndef likely
    #define likely(x) __builtin_expect((x), 1)
#endif
#ifndef unlikely
    #define unlikely(x) __builtin_expect((x), 0)
#endif

#endif
