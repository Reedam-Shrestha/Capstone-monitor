#ifndef MONITOR_FINAL_H
#define MONITOR_FINAL_H

#include <stdint.h>
#include <stdbool.h>
#include "sliding_window.h"

#define MAX_PIDS         256
#define MAX_CORES         64
#define DEFAULT_INTERVAL  50
#define DEFAULT_TOP_N    256   /* monitor all processes by default */
#define MIN_UID            0   /* include root processes by default */

/*
 * PidState — per-PID baseline counters for delta computation.
 *
 * prev_io_proc — baseline for /proc/PID/io bytes (read+write-cancelled).
 *   Used to compute smoothed_io_freq (bytes/sec).  Sourced from procfs so it
 *   correctly attributes buffered I/O to the originating task, unlike BPF
 *   block_rq_issue which fires in kworker context for writeback I/O.
 *
 * prev_io / prev_io_count — BPF block_rq_complete counters retained for
 *   pairing with io_wait_ns: they count direct-I/O completions where the
 *   BPF latency measurement is valid (issue fires in process context).
 *
 * prev_io_wait_ns — cumulative nanoseconds spent waiting for block I/O
 *   (sum of issue→complete deltas tracked in the BPF io_wait_ns map).
 *   Valid for direct I/O; 0 for writeback I/O (expected).
 *   Used to compute smoothed_io_wait_ms.
 *
 * prev_rq_wait_ns — snapshot of the cumulative runqueue wait nanoseconds
 *   (sum of wakeup→schedule deltas tracked in the BPF rq_wait_ns map).
 *   Used to compute smoothed_rq_wait_ms.
 *
 * prev_cpu_id — last cpu_id seen from ebpf_tracer_read_last_cpu().
 *   -1 means not yet observed.  Set to -1 on add_pid so the first interval
 *   never counts as a migration (we have no baseline to compare against).
 *   Does NOT require per-core perf fds — sourced from the BPF pid_last_cpu
 *   map which is updated by the sched_switch tracepoint on every reschedule.
 *
 * migration_count — number of cpu_id changes observed this slow-path
 *   interval (200ms).  Reset to 0 after each interval.  Divided by slow_dt
 *   to produce migration_freq (migrations/sec) before pushing to the window.
 */
typedef struct {
    int      pid;
    int      active;
    int      io_fd;             /* persistent fd for /proc/PID/io; -1 if unavailable */
    int      prev_cpu_id;       /* last seen cpu_id from BPF; -1 = not yet observed */
    uint32_t migration_count;   /* core changes this interval; reset each slow-path tick */
    uint64_t prev_cycles;
    uint64_t prev_instructions;
    uint64_t prev_llc;
    uint64_t prev_ctx;
    uint64_t prev_io_proc;      /* cumulative /proc/PID/io bytes (r+w-cancelled) */
    uint64_t prev_io;           /* cumulative BPF block_rq_complete count (direct I/O) */
    uint64_t prev_io_wait_ns;   /* cumulative block I/O wait nanoseconds     */
    uint64_t prev_rq_wait_ns;   /* cumulative runqueue wait nanoseconds      */
    uint64_t prev_io_count;     /* completion count at last prev_io_wait_ns  */
} PidState;

typedef struct {
    int   pids[MAX_PIDS];
    int   n_pids;
    int   top_n;
    int   min_uid;
    int   interval_ms;
    char *csv_path;
    char *label;          /* optional workload label for calibration CSV */
    bool  terminal_mode;
    bool  running;
    bool  per_core;       /* default: true */
    bool  show_zero;      /* show all-zero entries in terminal output */
    bool  no_shm;         /* skip ring buffer creation (CSV-only/calibration mode) */
} DaemonConfig;

#endif /* MONITOR_FINAL_H */
