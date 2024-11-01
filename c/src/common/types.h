#ifndef _NENP_TYPES_H_
#define _NENP_TYPES_H_

#include <stdint.h>
#include "macros.h"

typedef struct {
  uint64_t s_dev;
  uint64_t i_ino;
} fo_inode;

typedef struct {
  uint8_t path[FO_MAX_PATH];
  uint8_t path_meta[FO_MAX_DEFINITION];
  uint8_t padding[64 - FO_MAX_DEFINITION];
} fo_monitor_name;

#endif