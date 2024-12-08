#ifndef __LW_NAMESPACE_H__
#define __LW_NAMESPACE_H__

#define MNT_NS_ID(x) BPF_CORE_READ(x, mnt_ns, ns.inum)
#define UTS_NS_ID(x) BPF_CORE_READ(x, uts_ns, ns.inum)
#define IPC_NS_ID(x) BPF_CORE_READ(x, ipc_ns, ns.inum)
#define NET_NS_ID(x) BPF_CORE_READ(x, net_ns, ns.inum)
#define CGROUP_ID(x) BPF_CORE_READ(x, cgroup_ns, ns.inum)

#endif
