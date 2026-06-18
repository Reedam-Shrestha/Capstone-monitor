#ifndef PROC_SCANNER_H
#define PROC_SCANNER_H

#include <stdint.h>

#define PROC_MAX_TRACKED  1024   /* max PIDs we track for ranking */

/* One entry per process — what we read from /proc/PID/stat */
typedef struct {
    int      pid;
    char     comm[17];          /* process name, max 16 chars + null */
    int      uid;               /* from /proc/PID/status; -1 = not yet read */
    uint64_t utime;             /* user-mode CPU ticks (from stat) */
    uint64_t stime;             /* kernel-mode CPU ticks (from stat) */
    uint64_t total_ticks;       /* utime + stime */
    uint64_t prev_ticks;        /* previous interval total_ticks */
    uint64_t delta_ticks;       /* ticks consumed this interval */
    int      active;            /* 1 = seen in this scan */
} ProcEntry;

typedef struct {
    ProcEntry entries[PROC_MAX_TRACKED];
    int       n_entries;
    int       scan_count;       /* how many scans done so far */
} ProcScanner;

/* Initialise the scanner — zero all entries */
void proc_scanner_init(ProcScanner *ps);

/* Scan /proc, update deltas.
 * Call once per interval BEFORE calling proc_scanner_top_n. */
void proc_scanner_scan(ProcScanner *ps);
void proc_scanner_scan_pids(ProcScanner *ps, const uint32_t *pids, int num_pids);

/* Fill pids[] with the top N PIDs by delta_ticks.
 * Returns actual number written (may be less than n if fewer processes exist).
 * Skips PIDs with uid < min_uid to filter out kernel threads and root daemons.
 * Set min_uid=0 to include everything. */
int proc_scanner_top_n(const ProcScanner *ps,
                       int *pids, int n, int min_uid);

/* Print the current top N to stdout (for debugging) */
void proc_scanner_print(const ProcScanner *ps, int n);

#endif /* PROC_SCANNER_H */
