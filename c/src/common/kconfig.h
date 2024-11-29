#ifndef _LW_KCONFIG_H_
#define _LW_KCONFIG_H_

#include "common/int_types.h"

enum kconfig_key_e {
    ARCH_HAS_SYSCALL_WRAPPER = 1000U
};

// TODO: support get_kconfig.
static int get_kconfig(u32 key) {
  return 1;
}

#endif