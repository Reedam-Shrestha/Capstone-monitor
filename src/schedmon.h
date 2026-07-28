#ifndef MONITOR_FINAL_H
#define MONITOR_FINAL_H

#include <stdint.h>
#include <stdbool.h>
#include "sliding_window.h"

#define MAX_PIDS         256
#define DEFAULT_INTERVAL  50
#define DEFAULT_TOP_N    256
#define MIN_UID            0

/* per pid baselines used to compute deltas each interval.
 * prev_io_proc = read+write bytes from /proc/pid/io (physical disk)
 * prev_io_syscall = rchar+wchar from same file (includes cache hits,
 *   kept separate from prev_io_proc on purpose, different signal)
 * prev_io / prev_io_count = bpf block_rq_complete stuff, for pairing with
 *   io_wait_ns since that only works for direct io
 * prev_cpu_id = -1 until we see the pid once, so first interval never
 *   counts as a migration by accident
 */
typedef struct {
    int      pid;
    int      active;
    int      io_fd;
    int      prev_cpu_id;
    uint32_t migration_count;
    uint64_t prev_cycles;
    uint64_t prev_instructions;
    uint64_t prev_llc;
    uint64_t prev_ctx;
    uint64_t prev_io_proc;
    uint64_t prev_io_syscall;
    uint64_t prev_io;
    uint64_t prev_io_wait_ns;
    uint64_t prev_rq_wait_ns;
    uint64_t prev_io_count;
} PidState;

typedef struct {
    int   pids[MAX_PIDS];
    int   n_pids;
    int   top_n;
    int   min_uid;
    int   interval_ms;
    char *csv_path;
    char *label;
    bool  terminal_mode;
    bool  running;
    bool  show_zero;
} DaemonConfig;

#endif /* MONITOR_FINAL_H */