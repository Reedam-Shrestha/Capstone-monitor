#ifndef SMOOTHED_METRICS_H
#define SMOOTHED_METRICS_H

#include <stdint.h>

/*
 * ABI version — bump whenever the struct layout changes.
 * Consumers (classifier, ghOSt agent, dashboard) must check this at startup:
 *
 *   #include "smoothed_metrics.h"
 *   _Static_assert(MONITOR_ABI_VERSION == 4, "recompile against updated smoothed_metrics.h");
 */
#define MONITOR_ABI_VERSION  4

/*
 * SmoothedMetrics — one ring buffer slot.
 *
 * Memory layout (sizeof == 72, 8-byte aligned throughout):
 *   offset  0   int      pid
 *   offset  4   int      cpu_id        -1=aggregate, >=0=specific core
 *   offset  8   uint64_t timestamp_ns   CLOCK_MONOTONIC
 *   offset 16   double   smoothed_ipc
 *   offset 24   double   smoothed_llc_miss   fraction, NOT percent
 *   offset 32   double   smoothed_ctx_freq   voluntary switches/sec
 *   offset 40   double   smoothed_io_freq    disk bytes/sec (from /proc/PID/io)
 *   offset 48   double   smoothed_io_wait_ms avg block I/O wait latency ms
 *   offset 56   double   smoothed_rq_wait_ms avg runqueue wait latency ms
 *   offset 64   double   smoothed_migration_freq  core migrations/sec
 *   total  72 bytes
 *
 * NEW in v4 (vs v3 = 64 bytes):
 *   smoothed_migration_freq — how many times per second this process moved
 *       to a different CPU core.  Sourced from the BPF pid_last_cpu map:
 *       the slow path reads the last-seen cpu_id each 200ms interval and
 *       counts changes.  Does NOT require per-core perf fds — works even
 *       with --no-per-core.  High values (hundreds/sec) indicate scheduler
 *       instability; the process is being bounced across cores, destroying
 *       cache locality.  Primary signal for choosing between schedulers.
 *   smoothed_io_wait_ms  — average time (ms) a block I/O request spent
 *       waiting from issue to completion.  0.0 when block_rq_issue tracepoint
 *       is unavailable.  Distinguishes truly I/O-latency-bound processes
 *       (high wait) from I/O-throughput-bound ones (high freq, low wait).
 *
 *   smoothed_rq_wait_ms  — average time (ms) a runnable task waited on the
 *       CPU runqueue before being scheduled.  0.0 when sched_wakeup tracepoint
 *       is unavailable.  Primary signal for scheduler load-balance decisions:
 *       high rq_wait on CPU cores means the CPU pool is overloaded.
 *
 * All consumers MUST be compiled against this header.
 * Use MONITOR_ABI_VERSION to catch version skew at compile time.
 *
 * IMPORTANT — smoothed_io_freq is BYTES/SEC (not completions/sec).
 * It is sourced from /proc/PID/io (read_bytes + write_bytes - cancelled_write_bytes)
 * which correctly attributes buffered I/O to the originating task.
 * 0.0 for mmap-heavy processes (browsers, JVMs) — use smoothed_ctx_freq and
 * smoothed_io_wait_ms as I/O-bound signals for those workloads instead.
 */
typedef struct {
    int      pid;
    int      cpu_id;
    uint64_t timestamp_ns;
    double   smoothed_ipc;
    double   smoothed_llc_miss;
    double   smoothed_ctx_freq;
    double   smoothed_io_freq;       /* disk bytes/sec via /proc/PID/io; 0 for mmap I/O */
    double   smoothed_io_wait_ms;   /* avg block I/O latency ms; 0 if unavail  */
    double   smoothed_rq_wait_ms;   /* avg runqueue wait ms;     0 if unavail  */
    double   smoothed_migration_freq; /* core migrations/sec; 0 if pid_last_cpu unavail */
} SmoothedMetrics;

_Static_assert(sizeof(SmoothedMetrics) == 72,
    "SmoothedMetrics layout changed — update MONITOR_ABI_VERSION and SLOT in dashboard.py");

#endif /* SMOOTHED_METRICS_H */
