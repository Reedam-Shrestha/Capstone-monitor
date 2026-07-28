#ifndef SMOOTHED_METRICS_H
#define SMOOTHED_METRICS_H

#include <stdint.h>

/* bump this if struct layout changes, consumers should check it on startup */
#define MONITOR_ABI_VERSION  5

/*
 * one ring buffer slot, 88 bytes total (8 byte aligned)
 *
 * offset  0   pid
 * offset  4   cpu_id (-1 = aggregate, we dont do per-core anymore)
 * offset  8   hw_pmu_available (1 = real hw counters, 0 = software fallback)
 * offset 16   timestamp_ns (CLOCK_MONOTONIC)
 * offset 24   smoothed_ipc
 * offset 32   smoothed_llc_miss (fraction not percent)
 * offset 40   smoothed_ctx_freq
 * offset 48   smoothed_io_freq (bytes/sec, physical disk)
 * offset 56   smoothed_io_wait_ms
 * offset 64   smoothed_rq_wait_ms
 * offset 72   smoothed_migration_freq
 * offset 80   smoothed_io_syscall_freq
 *
 * hw_pmu_available matters because in software fallback mode ipc/llc_miss
 * are always 0 -- can't be distguished from an actually idle process
 * unless you check this flag first.
 *
 * smoothed_io_freq vs smoothed_io_syscall_freq are NOT the same thing.
 * io_freq = read_bytes+write_bytes from /proc/pid/io, only counts stuff
 * that hit the actual disk. io_syscall_freq = rchar+wchar, counts every
 * read/write syscall including page cache hits. a process reading a hot
 * cached file will have high syscall_freq and ~0 io_freq, thats fine and
 * expected, don't try to merge these two.
 */
typedef struct {
    int      pid;
    int      cpu_id;
    int      hw_pmu_available;
    uint64_t timestamp_ns;
    double   smoothed_ipc;
    double   smoothed_llc_miss;
    double   smoothed_ctx_freq;
    double   smoothed_io_freq;
    double   smoothed_io_wait_ms;
    double   smoothed_rq_wait_ms;
    double   smoothed_migration_freq;
    double   smoothed_io_syscall_freq;
} SmoothedMetrics;

_Static_assert(sizeof(SmoothedMetrics) == 88,
    "layout changed, update dashboard.py SLOT too");

#endif /* SMOOTHED_METRICS_H */