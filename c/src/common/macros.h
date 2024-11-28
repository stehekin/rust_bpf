#ifndef _LW_MACROS_H_
#define _LW_MACROS_H_

#define S_IFMT  00170000
#define S_IFREG  0100000
#define S_ISREG(m)	(((m) & S_IFMT) == S_IFREG)
#define S_ISDIR(m)	(((m) & S_IFMT) == S_IFDIR)

// Trailing 0 not included.
#define MAX_NAME_LEN 127

#define BPF_LOOP_STOP 1
#define BPF_LOOP_CONTINUE 0

#define TASK_COMM_LEN 16

#endif
