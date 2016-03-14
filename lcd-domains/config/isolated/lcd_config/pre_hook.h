/*
 * pre_hook.h
 *
 * This should be included at the top of every source
 * file that could possibly be built for the isolated
 * environment. It ensures the build configuration
 * is correct.
 *
 * This file should never be put in a header itself, only
 * in .c files. (We want this file to be included exactly
 * once before all other code.)
 */

#undef CONFIG_DEBUG_OBJECTS
#undef CONFIG_KMEMCHECK
#undef CONFIG_DEBUG_KMEMLEAK
#undef CONFIG_FAILSLAB
#undef CONFIG_SLOB
#undef CONFIG_SLUB
#undef CONFIG_NUMA
#undef CONFIG_NEED_MULTIPLE_NODES
#undef CONFIG_DEBUG_SLAB
#undef CONFIG_TRACING
#undef CONFIG_TRACEPOINTS
#undef CONFIG_FUNCTION_TRACER
#undef CONFIG_FUNCTION_GRAPH_TRACER
#undef CONFIG_SCHED_TRACER
#undef CONFIG_FTRACE_SYSCALLS
#undef CONFIG_TRACER_SNAPSHOT
#undef CONFIG_BRANCH_PROFILE_NONE
#undef CONFIG_STACK_TRACER
#undef CONFIG_BLK_DEV_IO_TRACE
#undef CONFIG_KPROBE_EVENT
#undef CONFIG_UPROBE_EVENT
#undef CONFIG_PROBE_EVENTS
#undef CONFIG_DYNAMIC_FTRACE
#undef CONFIG_DYNAMIC_FTRACE_WITH_REGS
#undef CONFIG_FUNCTION_PROFILER
#undef CONFIG_FTRACE_MCOUNT_RECORD
#undef CONFIG_FTRACE_STARTUP_TEST
#undef CONFIG_MMIOTRACE
#undef CONFIG_SLUB_DEBUG
#undef CONFIG_MEMCG_KMEM
#undef CONFIG_ZONE_DMA
#undef CONFIG_DEBUG_VM
#undef CONFIG_MEMCG
#undef CONFIG_MEMCG_KMEM
#undef CONFIG_CGROUP
#undef CONFIG_CGROUP_FREEZER
#undef CONFIG_CGROUP_DEVICE
#undef CONFIG_CPUSETS
#undef CONFIG_PROC_PID_CPUSET
#undef CONFIG_CGROUP_CPUACCT
#undef CONFIG_RESOURCE_COUNTERS
#undef CONFIG_CGROUP_PERF
#undef CONFIG_CGROUP_SCHED
#undef CONFIG_FAIR_GROUP_SCHED
#undef CONFIG_CFS_BANDWIDTH
#undef CONFIG_RT_GROUP_SCHED
#undef CONFIG_BLK_CGROUP
#undef CONFIG_SLABINFO
#undef CONFIG_LOCKDEP
#undef CONFIG_DEBUG_LOCK_ALLOC
#undef CONFIG_LOCK_STAT
#undef CONFIG_SMP
#undef CONFIG_X86_64_SMP
#undef CONFIG_USE_GENERIC_SMP_HELPERS
#define CONFIG_NEED_PER_CPU_KM
#undef CONFIG_KALLSYMS
#undef CONFIG_SWAP
#undef CONFIG_TRANSPARENT_HUGEPAGE
#undef CONFIG_AUDITSYSCALL

#ifndef CONFIG_SLAB
#define CONFIG_SLAB
#endif

#undef CONFIG_NR_CPUS
#define CONFIG_NR_CPUS 1

#undef CONFIG_NODES_SHIFT /* force max numnodes to 1 */

/*
 * Set include guards to force using our includes.
 */
#ifndef MM_SLAB_H
#define MM_SLAB_H
#endif
#ifndef __MM_INTERNAL_H
#define __MM_INTERNAL_H
#endif

