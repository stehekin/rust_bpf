#ifndef __LW_INT_TYPES_H__
#define __LW_INT_TYPES_H__

typedef signed char __s8;
typedef unsigned char __u8;

typedef short int __s16;
typedef short unsigned int __u16;
typedef __u16 __le16;
typedef __u16 __be16;

typedef int __s32;
typedef unsigned int __u32;
typedef __u32 int32;
typedef __u32 __be32;

typedef long long int __s64;
typedef long long unsigned int __u64;
typedef __u64 __le64;
typedef __u64 __be64;

typedef __s8 s8;
typedef __u8 u8;

typedef __s16 s16;
typedef __u16 u16;

typedef __s32 s32;
typedef __u32 u32;

typedef __s64 s64;
typedef __u64 u64;

typedef __u32 __wsum;

typedef int __kernel_pid_t;

typedef __kernel_pid_t pid_t;

typedef enum {
  false = 0,
  true = 1
} bool;

#endif