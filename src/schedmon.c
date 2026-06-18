#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/syscall.h>
#include <errno.h>
#include "perf_counter.h"
#include "ebpf_tracer.h"
#include "sliding_window.h"
#include "ring_buffer.h"
#include "smoothed_metrics.h"
#include "proc_scanner.h"
#include "schedmon.h"

/* ── Timing and threshold constants ────────────────────────────────────── */

/* A process is considered stale if not updated within this window.
 * 1 second = 5× the 200ms slow-path interval. */
#define STALE_NS          1000000000ULL

/* Maximum plausible runqueue wait per wakeup event.
 * 10 seconds is impossible in normal scheduling — guards against
 * timestamp wrap or PID reuse that wasn't caught by the monotonicity check. */
#define RQ_WAIT_MAX_NS    10000000000ULL

/* Maximum plausible block I/O latency.
 * 30 seconds exceeds any reasonable disk timeout — clamps corrupt timestamps. */
#define IO_WAIT_MAX_NS    30000000000ULL

/* Maximum valid PID on Linux (from /proc/sys/kernel/pid_max, default 4194304) */
#define LINUX_PID_MAX     4194304

/* ── Global state ───────────────────────────────────────────────────────── */

static DaemonConfig   g_cfg;
static PidState       g_states [MAX_PIDS];
static SlidingWindow  g_win_ipc[MAX_PIDS];
static SlidingWindow  g_win_llc[MAX_PIDS];
static SlidingWindow  g_win_ctx[MAX_PIDS];
static SlidingWindow  g_win_io [MAX_PIDS];
static SlidingWindow  g_win_io_wait[MAX_PIDS];   /* avg I/O wait latency ms  */
static SlidingWindow  g_win_rq_wait[MAX_PIDS];   /* avg runqueue wait ms      */
static SlidingWindow  g_win_migration[MAX_PIDS]; /* core migrations/sec       */

static perf_counter_t g_perf   [MAX_PIDS];                    /* aggregate    */
static perf_counter_t g_perf_pc[MAX_PIDS][MAX_CORES];         /* per-core     */

static SlidingWindow  g_win_ipc_pc[MAX_PIDS][MAX_CORES];
static SlidingWindow  g_win_llc_pc[MAX_PIDS][MAX_CORES];

typedef struct {
    uint64_t prev_cycles;
    uint64_t prev_instr;
    uint64_t prev_llc;
} CorePrev;
static CorePrev g_core_prev[MAX_PIDS][MAX_CORES];

/*
 * Fast-path cache — slow path (200ms) fills these; fast path (50ms) stamps
 * a fresh timestamp and pushes them to the ring buffers.
 *
 * BUG 2 FIX: track when each slot was last written by the slow path.
 * Fast path skips entries not updated within STALE_NS (1 second = 5×
 * slow-path interval).  Without this, sleeping processes push stale
 * IPC/LLC values with fresh timestamps, misleading the classifier into
 * thinking they are active.
 * STALE_NS is defined at the top of the file with other timing constants.
 */

static SmoothedMetrics g_last_sm   [MAX_PIDS];
static SmoothedMetrics g_last_sm_pc[MAX_PIDS][MAX_CORES];
static uint64_t        g_last_sm_updated_ns[MAX_PIDS];         /* BUG2 fix */
static bool            g_last_sm_valid     [MAX_PIDS];         /* BUG2 fix */
static char            g_comm      [MAX_PIDS][17];

static int            g_ncores  = 0;
static ebpf_tracer_t  g_tracer;
static RingBuffer    *g_rb      = NULL;   /* classifier  — aggregate only  */
static RingBuffer    *g_rb_dash = NULL;   /* dashboard   — agg + per-core  */
static RingBuffer    *g_rb_sched= NULL;   /* scheduler   — per-core only   */
static FILE          *g_csv     = NULL;
static int            g_n_active = 0;
static ProcScanner    g_scanner;

static volatile sig_atomic_t g_running = 0;
static void handle_signal(int sig) { (void)sig; g_running = 0; }

/* ── read_proc_io ────────────────────────────────────────────────────────────
 * Read /proc/PID/io using a persistent fd stored in PidState.
 *
 * WHY persistent fd instead of fopen/fclose:
 *   With 256 PIDs at 200ms cadence, fopen/fclose costs 1,280 VFS operations
 *   per second.  Under disk pressure (when io_freq matters most) this adds
 *   measurable latency to the sampling loop.  Keeping the fd open and using
 *   lseek(SEEK_SET,0) + read() is ~10x faster and avoids path resolution.
 *
 * WHY /proc/PID/io (same as before):
 *   Correctly attributes buffered I/O to the originating task at submit_bio
 *   time — same mechanism as iotop.  BPF block_rq_issue fires in kworker
 *   context for writeback I/O, not the app's context.
 *
 * fd=-1 means the file is unavailable (process exited or no CAP_SYS_PTRACE).
 * Returns 0 on any failure.
 */
/* Sentinel: returned when the fd is unreadable (process exited, permissions lost).
 * Distinct from 0, which is a valid value for a process that has done no I/O.
 * Callers check for PROC_IO_READ_FAIL before treating the result as a byte count
 * so that genuinely idle processes (0 bytes I/O) do not trigger a stale-fd reopen. */
#define PROC_IO_READ_FAIL  UINT64_MAX

static uint64_t read_proc_io_fd(int fd) {
    if (fd < 0) return PROC_IO_READ_FAIL;

    char buf[256];
    if (lseek(fd, 0, SEEK_SET) < 0) return PROC_IO_READ_FAIL;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return PROC_IO_READ_FAIL;
    buf[n] = '\0';

    uint64_t read_bytes = 0, write_bytes = 0, cancelled = 0;
    char *p = buf;
    while (*p) {
        if (strncmp(p, "read_bytes:", 11) == 0)
            read_bytes = strtoull(p + 11, NULL, 10);
        else if (strncmp(p, "write_bytes:", 12) == 0)
            write_bytes = strtoull(p + 12, NULL, 10);
        else if (strncmp(p, "cancelled_write_bytes:", 22) == 0)
            cancelled = strtoull(p + 22, NULL, 10);
        /* advance to next line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }

    uint64_t total = read_bytes + write_bytes;
    return (total >= cancelled) ? (total - cancelled) : 0;
}

static int g_io_fd_fail_count = 0;  /* how many PIDs couldn't open /proc/PID/io */
static int g_io_fd_ok_count   = 0;  /* how many PIDs successfully opened it */

/* Open /proc/PID/io and return the fd, or -1 on failure.
 * Called once from add_pid; fd is stored in PidState.io_fd. */
static int open_proc_io_fd(int pid) {
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/io", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        g_io_fd_fail_count++;
        /* Print a warning on the first failure and every 50th after that,
         * so the journal doesn't get flooded but the problem is visible. */
        if (g_io_fd_fail_count == 1 || g_io_fd_fail_count % 50 == 0)
            fprintf(stderr,
                "[daemon] open(%s) failed: %s  "
                "(fail_count=%d ok_count=%d)\n"
                "  io_freq will be 0. Add CAP_SYS_PTRACE to service if needed.\n",
                path, strerror(errno),
                g_io_fd_fail_count, g_io_fd_ok_count);
    } else {
        g_io_fd_ok_count++;
    }
    return fd;
}

/* ── read_proc_comm ─────────────────────────────────────────────────────── */

static void read_proc_comm(int pid, char *buf, int len) {
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { buf[0] = '\0'; return; }
    ssize_t n = read(fd, buf, len - 1);
    close(fd);
    if (n > 0) {
        if (buf[n-1] == '\n') n--;
        buf[n] = '\0';
    } else {
        buf[0] = '\0';
    }
}

/* ── parse_args ─────────────────────────────────────────────────────────── */

static void parse_args(int argc, char **argv) {
    g_cfg.interval_ms   = DEFAULT_INTERVAL;
    g_cfg.terminal_mode = false;
    g_cfg.n_pids        = 0;
    g_cfg.top_n         = 0;
    g_cfg.min_uid       = MIN_UID;
    g_cfg.csv_path      = NULL;
    g_cfg.label         = NULL;
    g_cfg.per_core      = true;
    g_cfg.show_zero     = false;
    g_cfg.no_shm        = false;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--pids") == 0 && i + 1 < argc) {
            i++;
            char *saveptr = NULL;
            char *tok = strtok_r(argv[i], ",", &saveptr);
            while (tok && g_cfg.n_pids < MAX_PIDS) {
                char *end;
                long v = strtol(tok, &end, 10);
                if (end == tok || *end != '\0' || v <= 0 || v > LINUX_PID_MAX) {
                    fprintf(stderr, "[daemon] invalid PID '%s' — skipping\n", tok);
                } else {
                    g_cfg.pids[g_cfg.n_pids++] = (int)v;
                }
                tok = strtok_r(NULL, ",", &saveptr);
            }
        } else if (strcmp(argv[i], "--top") == 0 && i + 1 < argc) {
            g_cfg.top_n = atoi(argv[++i]);
            if (g_cfg.top_n <= 0 || g_cfg.top_n > MAX_PIDS)
                g_cfg.top_n = DEFAULT_TOP_N;
        } else if (strcmp(argv[i], "--interval") == 0 && i + 1 < argc) {
            g_cfg.interval_ms = atoi(argv[++i]);
            if (g_cfg.interval_ms <= 0) g_cfg.interval_ms = DEFAULT_INTERVAL;
        } else if (strcmp(argv[i], "--csv") == 0 && i + 1 < argc) {
            g_cfg.csv_path = argv[++i];
        } else if (strcmp(argv[i], "--min-uid") == 0 && i + 1 < argc) {
            g_cfg.min_uid = atoi(argv[++i]);
        } else if (strcmp(argv[i], "--no-per-core") == 0) {
            /* Opt out of per-core mode (e.g. on VMs with limited perf FDs) */
            g_cfg.per_core = false;
        } else if (strcmp(argv[i], "--per-core") == 0) {
            g_cfg.per_core = true;   /* explicit, same as default */
        } else if (strcmp(argv[i], "--no-shm") == 0) {
            /* Skip ring buffer creation entirely.
             * Used by calibrate.py so it does not destroy the production
             * /monitor_rb, /monitor_rb_dash, /monitor_rb_sched shm objects
             * that the dashboard and classifier are attached to.
             * In this mode only --csv output is produced. */
            g_cfg.no_shm = true;
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            /* Workload label written to CSV for calibration/training.
             * Example: --csv cpu.csv --label cpu_bound
             * Bigyan's classifier can use these labeled CSVs as ground truth. */
            g_cfg.label = argv[++i];
        } else if (strcmp(argv[i], "--terminal") == 0) {
            g_cfg.terminal_mode = true;
        } else if (strcmp(argv[i], "--zero") == 0 ||
                   strcmp(argv[i], "-z") == 0) {
            /* Show all-zero (idle/sleeping) processes in terminal output.
             * Does not affect ring buffer — zeros are never pushed there. */
            g_cfg.show_zero = true;
        }
    }

    if (g_cfg.n_pids == 0 && g_cfg.top_n == 0)
        g_cfg.top_n = DEFAULT_TOP_N;
}

/* ── slot management ────────────────────────────────────────────────────── */

static int find_slot(int pid) {
    for (int i = 0; i < g_n_active; i++)
        if (g_states[i].pid == pid) return i;
    return -1;
}

static int add_pid(int pid) {
    if (g_n_active >= MAX_PIDS) return -1;
    int i = g_n_active;

    /* Clear stale data BEFORE opening counters */
    memset(&g_perf[i], 0, sizeof(g_perf[i]));
    g_perf[i].fd_cycles = g_perf[i].fd_instr = g_perf[i].fd_llc = -1;

    if (g_cfg.per_core) {
        for (int c = 0; c < g_ncores; c++) {
            memset(&g_perf_pc[i][c], 0, sizeof(g_perf_pc[i][c]));
            g_perf_pc[i][c].fd_cycles =
            g_perf_pc[i][c].fd_instr  =
            g_perf_pc[i][c].fd_llc    = -1;
        }
    }

    if (perf_counter_open(&g_perf[i], (pid_t)pid, -1) != 0) {
        fprintf(stderr, "[daemon] perf_counter_open failed for PID %d\n", pid);
        perf_counter_close(&g_perf[i]);
        return -1;
    }

    if (g_cfg.per_core && g_perf[i].hw_available) {
        for (int c = 0; c < g_ncores; c++) {
            if (perf_counter_open(&g_perf_pc[i][c], (pid_t)pid, c) == 0) {
                sw_init(&g_win_ipc_pc[i][c]);
                sw_init(&g_win_llc_pc[i][c]);
            } else {
                perf_counter_close(&g_perf_pc[i][c]);
            }
        }
    }

    memset(&g_states[i],     0, sizeof(g_states[i]));
    memset(g_core_prev[i],   0, sizeof(g_core_prev[i]));
    memset(&g_last_sm[i],    0, sizeof(g_last_sm[i]));
    memset(g_last_sm_pc[i],  0, sizeof(g_last_sm_pc[i]));
    g_states[i].io_fd         = -1;   /* must set after memset; 0 = stdin, not "no fd" */
    g_states[i].prev_cpu_id   = -1;   /* no baseline yet — first interval skips migration count */
    g_states[i].migration_count = 0;
    g_comm[i][0]              = '\0';
    g_last_sm_valid[i]        = false;    /* BUG2 fix */
    g_last_sm_updated_ns[i]   = 0;        /* BUG2 fix */

    g_states[i].pid    = pid;
    g_states[i].active = 1;
    sw_init(&g_win_ipc[i]);
    sw_init(&g_win_llc[i]);
    sw_init(&g_win_ctx[i]);
    sw_init(&g_win_io[i]);
    sw_init(&g_win_io_wait[i]);
    sw_init(&g_win_rq_wait[i]);
    sw_init(&g_win_migration[i]);

    /* Seed baselines so first delta ≈ 0 */
    raw_counters_t seed;
    if (perf_counter_read(&g_perf[i], &seed) == 0) {
        g_states[i].prev_cycles       = seed.cycles;
        g_states[i].prev_instructions = seed.instructions;
        g_states[i].prev_llc          = seed.llc_misses;
    }
    g_states[i].prev_ctx        = ebpf_tracer_read_switches  (&g_tracer, (uint32_t)pid);
    g_states[i].prev_io         = ebpf_tracer_read_io         (&g_tracer, (uint32_t)pid);
    g_states[i].prev_io_wait_ns = ebpf_tracer_read_io_wait_ns (&g_tracer, (uint32_t)pid);
    g_states[i].prev_rq_wait_ns = ebpf_tracer_read_rq_wait_ns (&g_tracer, (uint32_t)pid);
    g_states[i].prev_io_count   = g_states[i].prev_io;
    /* Open persistent /proc/PID/io fd — keep it open for the lifetime of this
     * slot to avoid 1,280 fopen/fclose calls per second across 256 PIDs. */
    g_states[i].io_fd = open_proc_io_fd(pid);
    if (g_states[i].io_fd >= 0) {
        uint64_t seed_io = read_proc_io_fd(g_states[i].io_fd);
        /* Treat read failure as 0 for baseline seeding; first delta will be 0. */
        g_states[i].prev_io_proc = (seed_io == PROC_IO_READ_FAIL) ? 0 : seed_io;
    } else {
        g_states[i].prev_io_proc = 0;
    }

    if (!ebpf_tracer_pop_exec_comm(&g_tracer, (uint32_t)pid,
                                   g_comm[i], sizeof(g_comm[i])))
        read_proc_comm(pid, g_comm[i], sizeof(g_comm[i]));

    /* Register in BPF active_pids map so block_rq_issue/complete tracepoints
     * track this PID even if it was created before the daemon started. */
    ebpf_tracer_register_pid(&g_tracer, (uint32_t)pid);

    g_n_active++;
    return i;
}

static void remove_slot(int i) {
    /* Unregister from BPF active_pids so block tracepoints stop tracking
     * this PID as soon as we stop monitoring it. */
    ebpf_tracer_unregister_pid(&g_tracer, (uint32_t)g_states[i].pid);

    /* Close persistent /proc/PID/io fd */
    if (g_states[i].io_fd >= 0) {
        close(g_states[i].io_fd);
        g_states[i].io_fd = -1;
    }

    perf_counter_close(&g_perf[i]);
    if (g_cfg.per_core)
        for (int c = 0; c < g_ncores; c++)
            perf_counter_close(&g_perf_pc[i][c]);

    int last = g_n_active - 1;
    if (i != last) {
        g_states           [i] = g_states           [last];
        g_win_ipc          [i] = g_win_ipc          [last];
        g_win_llc          [i] = g_win_llc          [last];
        g_win_ctx          [i] = g_win_ctx          [last];
        g_win_io           [i] = g_win_io           [last];
        g_win_io_wait      [i] = g_win_io_wait      [last];
        g_win_rq_wait      [i] = g_win_rq_wait      [last];
        g_win_migration    [i] = g_win_migration    [last];
        g_perf             [i] = g_perf             [last];
        g_last_sm          [i] = g_last_sm          [last];
        g_last_sm_valid    [i] = g_last_sm_valid    [last];   /* BUG3 fix */
        g_last_sm_updated_ns[i]= g_last_sm_updated_ns[last]; /* BUG3 fix */
        memcpy(g_comm[i],         g_comm[last],         sizeof(g_comm[i]));
        memcpy(g_last_sm_pc[i],   g_last_sm_pc[last],   sizeof(g_last_sm_pc[i]));
        for (int c = 0; c < g_ncores; c++) {
            g_perf_pc   [i][c] = g_perf_pc   [last][c];
            g_win_ipc_pc[i][c] = g_win_ipc_pc[last][c];
            g_win_llc_pc[i][c] = g_win_llc_pc[last][c];
            g_core_prev [i][c] = g_core_prev [last][c];
        }
    }
    /* BUG3 fix: clear last slot so a future add_pid at that index starts clean */
    g_last_sm_valid    [last] = false;
    g_last_sm_updated_ns[last] = 0;
    g_n_active--;
}

/* ── sync_pids ──────────────────────────────────────────────────────────── */

static void sync_pids(void) {
    static struct timespec last_sync;
    static int first_run = 1;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    int64_t elapsed_ns = (int64_t)(now.tv_sec  - last_sync.tv_sec)  * 1000000000LL
                       + (int64_t)(now.tv_nsec - last_sync.tv_nsec);
    if (!first_run && elapsed_ns < 1000000000LL) return;
    first_run = 0;
    last_sync = now;

    /* Full /proc scan only needed for top-N mode to rank processes by CPU.
     * In --pids mode, use the targeted scan that only reads the specified PIDs. */
    if (g_cfg.n_pids == 0) {
        proc_scanner_scan(&g_scanner);
    } else {
        /* Cast needed: g_cfg.pids is int[], scan_pids expects uint32_t[] */
        uint32_t upids[MAX_PIDS];
        for (int i = 0; i < g_cfg.n_pids; i++)
            upids[i] = (uint32_t)g_cfg.pids[i];
        proc_scanner_scan_pids(&g_scanner, upids, g_cfg.n_pids);
    }

    if (g_cfg.n_pids > 0) {
        for (int i = 0; i < g_cfg.n_pids; i++) {
            if (find_slot(g_cfg.pids[i]) < 0)
                add_pid(g_cfg.pids[i]);
        }
        for (int i = 0; i < g_n_active; ) {
            if (kill(g_states[i].pid, 0) == -1 && errno == ESRCH)
                remove_slot(i);
            else
                i++;
        }
    } else {
        int top[MAX_PIDS];
        int fetch_n = (g_cfg.top_n > MAX_PIDS) ? MAX_PIDS : g_cfg.top_n;
        int n = proc_scanner_top_n(&g_scanner, top, fetch_n, g_cfg.min_uid);

        for (int i = 0; i < g_n_active; i++) g_states[i].active = 0;
        for (int i = 0; i < n; i++) {
            int slot = find_slot(top[i]);
            if (slot < 0) slot = add_pid(top[i]);
            if (slot >= 0) g_states[slot].active = 1;
        }
        for (int i = 0; i < g_n_active; ) {
            if (g_states[i].active == 0) remove_slot(i);
            else i++;
        }
    }
}

/* ── init ───────────────────────────────────────────────────────────────── */

static void init_ebpf(const char *bpf_path) {
    if (ebpf_tracer_load(&g_tracer, bpf_path) != 0) {
        fprintf(stderr, "[daemon] FATAL: cannot load eBPF from '%s'\n", bpf_path);
        fprintf(stderr, "  Hint: absolute path, e.g. /opt/schedmon/bpf/ctx_switch.bpf.o\n");
        exit(1);
    }
    if (ebpf_tracer_attach(&g_tracer) != 0) {
        fprintf(stderr, "[daemon] FATAL: cannot attach eBPF\n");
        ebpf_tracer_destroy(&g_tracer);
        exit(1);
    }
}

static void init_shm(void) {
    if (g_cfg.no_shm) {
        /* --no-shm: CSV-only mode used by calibrate.py.
         * Skip ring buffer creation entirely so we don't destroy the
         * production shm objects that the dashboard/classifier are using.
         * g_rb, g_rb_dash, g_rb_sched remain NULL; all rb_push calls
         * are guarded by NULL checks and will silently no-op. */
        printf("[daemon] --no-shm: ring buffers disabled (CSV-only mode)\n");
        return;
    }
    g_rb = rb_create();
    if (!g_rb) { fprintf(stderr, "[daemon] FATAL: cannot create shm\n"); exit(1); }
    g_rb_dash = rb_create_dash();
    if (!g_rb_dash) { fprintf(stderr, "[daemon] FATAL: cannot create dash shm\n"); exit(1); }
    g_rb_sched = rb_create_sched();
    if (!g_rb_sched) { fprintf(stderr, "[daemon] FATAL: cannot create sched shm\n"); exit(1); }
    printf("[daemon] Ring buffers ready: %s  %s  %s\n",
           SHM_NAME, SHM_NAME_DASH, SHM_NAME_SCHED);
}

/* ── check_proc_io_access ───────────────────────────────────────────────────
 * Tests whether /proc/PID/io is readable at startup.
 * /proc/PID/io requires CAP_SYS_PTRACE regardless of root status.
 * Under systemd with NoNewPrivileges=yes this capability must be explicitly
 * listed in AmbientCapabilities — CAP_DAC_READ_SEARCH is not sufficient.
 *
 * Tests three cases:
 *   1. /proc/self/io  — always readable if the kernel supports it
 *   2. /proc/1/io     — readable only with CAP_SYS_PTRACE (PID 1 = systemd/init)
 *   3. /proc/<non-root-pid>/io — readable only with CAP_SYS_PTRACE
 *
 * Prints a clear diagnostic to stderr so it appears in journalctl.
 * Does not exit — io_freq will just be 0 if this fails.
 */
static void check_proc_io_access(void) {
    /* Test 1: /proc/self/io — sanity check that procfs io accounting is on */
    {
        int fd = open("/proc/self/io", O_RDONLY);
        if (fd < 0) {
            fprintf(stderr,
                "[daemon] WARNING: /proc/self/io not readable (%s)\n"
                "  io_freq will be 0 for all processes.\n"
                "  Kernel may be built without CONFIG_TASK_IO_ACCOUNTING.\n",
                strerror(errno));
            return;
        }
        close(fd);
    }

    /* Test 2: /proc/1/io — requires CAP_SYS_PTRACE */
    {
        int fd = open("/proc/1/io", O_RDONLY);
        if (fd < 0) {
            fprintf(stderr,
                "[daemon] WARNING: /proc/1/io not readable (%s)\n"
                "  io_freq will be 0 for all non-root processes.\n"
                "  FIX: add CAP_SYS_PTRACE to AmbientCapabilities and\n"
                "  CapabilityBoundingSet in schedmon.service, then:\n"
                "    sudo systemctl daemon-reload\n"
                "    sudo systemctl restart schedmon\n",
                strerror(errno));
            return;
        }
        close(fd);
    }

    /* Test 3: find a non-root PID and try to open its /proc/PID/io */
    {
        DIR *d = opendir("/proc");
        int found_pid = -1;
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL && found_pid < 0) {
                if (!isdigit(ent->d_name[0])) continue;
                int pid = atoi(ent->d_name);
                if (pid <= 1) continue;
                /* Check if this process is owned by a non-root user */
                char status_path[32];
                snprintf(status_path, sizeof(status_path), "/proc/%d/status", pid);
                FILE *f = fopen(status_path, "r");
                if (!f) continue;
                char line[128];
                while (fgets(line, sizeof(line), f)) {
                    if (strncmp(line, "Uid:", 4) == 0) {
                        int uid = atoi(line + 4);
                        if (uid > 0) { found_pid = pid; }
                        break;
                    }
                }
                fclose(f);
            }
            closedir(d);
        }

        if (found_pid > 0) {
            char io_path[32];
            snprintf(io_path, sizeof(io_path), "/proc/%d/io", found_pid);
            int fd = open(io_path, O_RDONLY);
            if (fd < 0) {
                fprintf(stderr,
                    "[daemon] WARNING: %s not readable (%s)\n"
                    "  io_freq will be 0 for non-root processes (pid %d, uid>0).\n"
                    "  FIX: add CAP_SYS_PTRACE to AmbientCapabilities and\n"
                    "  CapabilityBoundingSet in schedmon.service, then:\n"
                    "    sudo systemctl daemon-reload\n"
                    "    sudo systemctl restart schedmon\n",
                    io_path, strerror(errno), found_pid);
                return;
            }
            close(fd);
        }
    }

    printf("[daemon] /proc/PID/io access OK — io_freq metrics enabled\n");
}

/* ── sm_is_active ───────────────────────────────────────────────────────────
 * Returns true if at least one metric in m is non-zero.
 * Used to filter all-zero entries from the ring buffers so Bigyan's
 * classifier doesn't receive noise from idle/sleeping processes.
 * The dashboard can opt-in to seeing zeros with --zero / -z.
 */
static inline bool sm_is_active(const SmoothedMetrics *m) {
    return m->smoothed_ipc       > 0.0
        || m->smoothed_llc_miss  > 0.0
        || m->smoothed_ctx_freq  > 0.0
        || m->smoothed_io_freq   > 0.0
        || m->smoothed_io_wait_ms > 0.0
        || m->smoothed_rq_wait_ms > 0.0
        || m->smoothed_migration_freq > 0.0;
}

/* ── sampling loop ──────────────────────────────────────────────────────── */

static void run_sampling_loop(void) {
    int sample_num = 0;
    int first_slow = 1;
    struct timespec last_slow = {0,0};
    clock_gettime(CLOCK_MONOTONIC, &last_slow);  /* seed with real time so first slow_dt ≈ 0.200s */

    if (g_cfg.terminal_mode)
        printf("%-6s  %-4s  %-16s  %-7s  %-9s  %-9s  %-9s  %-10s  %-10s  %-10s\n",
               "PID", "CORE", "COMM",
               "IPC", "LLC%", "ctx/s", "io/s", "io_wait_ms", "rq_wait_ms", "mig/s");

    while (g_running) {
        struct timespec t_start;
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        uint64_t now_ns = (uint64_t)t_start.tv_sec * 1000000000ULL
                        + (uint64_t)t_start.tv_nsec;

        /* ════════════════════════════════════════════════════════════
         * SLOW PATH — every 4th tick (200ms)
         * ════════════════════════════════════════════════════════════ */
        if (sample_num % 4 == 0) {
            double slow_dt = 0.200;  // default

            if (!first_slow) {
                int64_t slow_dt_ns = (int64_t)(t_start.tv_sec - last_slow.tv_sec) * 1000000000LL;
                slow_dt_ns += (int64_t)t_start.tv_nsec - (int64_t)last_slow.tv_nsec;
                if (slow_dt_ns > 0) {
                    slow_dt = (double)slow_dt_ns * 1e-9;
                }
            } else {
                first_slow = 0;
            }
            last_slow = t_start;

            sync_pids();

            /* display_limit gates TERMINAL OUTPUT only — not metrics computation.
             * All g_n_active slots must have their perf fds drained every interval.
             * If a slot is skipped, its perf counters keep accumulating and the
             * first delta after it re-enters the display set is inflated. */
            int display_limit = g_cfg.top_n > 0 ? g_cfg.top_n : g_n_active;
            int displayed = 0;

            for (int i = 0; i < g_n_active; i++) {
                int pid = g_states[i].pid;

                raw_counters_t cur_hw;
                if (perf_counter_read(&g_perf[i], &cur_hw) != 0) {
                    remove_slot(i--); continue;
                }

                uint64_t cur_ctx        = ebpf_tracer_read_switches  (&g_tracer, (uint32_t)pid);
                uint64_t cur_io_wait_ns = ebpf_tracer_read_io_wait_ns (&g_tracer, (uint32_t)pid);
                uint64_t cur_rq_wait_ns = ebpf_tracer_read_rq_wait_ns (&g_tracer, (uint32_t)pid);

                /* Monotonicity guard: BPF counters reset on PID reuse (a new process
                 * gets the same PID as a recently-exited one).  If any counter went
                 * backwards, reset the baseline and skip this interval — the next
                 * interval will produce a correct delta from the new baseline. */
                if (cur_ctx        < g_states[i].prev_ctx        ||
                    cur_io_wait_ns < g_states[i].prev_io_wait_ns ||
                    cur_rq_wait_ns < g_states[i].prev_rq_wait_ns) {
                    g_states[i].prev_ctx        = cur_ctx;
                    g_states[i].prev_io_wait_ns = cur_io_wait_ns;
                    g_states[i].prev_rq_wait_ns = cur_rq_wait_ns;
                    /* Also reset hw baselines to avoid IPC spike */
                    g_states[i].prev_cycles       = cur_hw.cycles;
                    g_states[i].prev_instructions = cur_hw.instructions;
                    g_states[i].prev_llc          = cur_hw.llc_misses;
                    continue;
                }

                uint64_t d_cycles = cur_hw.cycles       - g_states[i].prev_cycles;
                uint64_t d_instr  = cur_hw.instructions - g_states[i].prev_instructions;
                uint64_t d_llc    = cur_hw.llc_misses   - g_states[i].prev_llc;

                /* Hardware counter wraparound / PMU reset guard.
                 * If cycles went backwards the counter was reset (e.g. process
                 * migrated to a different PMU domain, or perf fd was reset).
                 * Treat this interval as invalid — reset baselines and skip. */
                if (cur_hw.cycles < g_states[i].prev_cycles) {
                    g_states[i].prev_cycles       = cur_hw.cycles;
                    g_states[i].prev_instructions = cur_hw.instructions;
                    g_states[i].prev_llc          = cur_hw.llc_misses;
                    /* Also advance ctx/io baselines to stay consistent */
                    g_states[i].prev_ctx        = cur_ctx;
                    g_states[i].prev_io_wait_ns = cur_io_wait_ns;
                    g_states[i].prev_rq_wait_ns = cur_rq_wait_ns;
                    continue;
                }
                uint64_t d_ctx    = cur_ctx              - g_states[i].prev_ctx;

                /* rq wait: delta ns / slow_dt → avg ms per period
                 * We report it as average wait per schedule event; the
                 * classifier can use raw ms or normalize by period. */
                uint64_t d_rq_wait_ns = cur_rq_wait_ns - g_states[i].prev_rq_wait_ns;

                /* Always advance hw counter baselines — must happen before
                 * any continue so the next interval's delta is correct */
                g_states[i].prev_cycles       = cur_hw.cycles;
                g_states[i].prev_instructions = cur_hw.instructions;
                g_states[i].prev_llc          = cur_hw.llc_misses;

                /* Always advance ctx baseline */
                g_states[i].prev_ctx = cur_ctx;

                /* Seed PID field so fast path knows this slot is in use */
                if (g_last_sm[i].pid == 0) {
                    g_last_sm[i].pid    = pid;
                    g_last_sm[i].cpu_id = -1;
                }

                /* ── I/O metrics — computed regardless of d_cycles ──────────
                 * io_freq: sourced from /proc/PID/io (read_bytes + write_bytes
                 * - cancelled_write_bytes).  This correctly attributes buffered
                 * I/O to the originating process even when the actual block
                 * request is submitted later by kworker in writeback context.
                 * BPF block_rq_issue only captures direct I/O (O_DIRECT) which
                 * fires in the process's own context — hence BPF io_counts showed
                 * 0 for most processes that use the page cache.
                 *
                 * io_wait_ms: kept from BPF (latency of direct-I/O requests).
                 * For writeback I/O this will be 0, which is correct — the process
                 * is not synchronously blocked on the disk in that case. */
                uint64_t cur_io_proc = 0;
                if (g_states[i].io_fd >= 0) {
                    cur_io_proc = read_proc_io_fd(g_states[i].io_fd);

                    /* PROC_IO_READ_FAIL means the fd is stale (process exited,
                     * PID reused, or permissions lost) — NOT that the process
                     * has done zero bytes of I/O.  Only reopen on actual read
                     * failure, never on a legitimately zero I/O count. */
                    if (cur_io_proc == PROC_IO_READ_FAIL) {
                        close(g_states[i].io_fd);
                        g_states[i].io_fd = open_proc_io_fd(g_states[i].pid);
                        if (g_states[i].io_fd >= 0) {
                            cur_io_proc = read_proc_io_fd(g_states[i].io_fd);
                            /* If second read also fails, treat as 0 bytes this interval */
                            if (cur_io_proc == PROC_IO_READ_FAIL) cur_io_proc = 0;
                        } else {
                            cur_io_proc = 0;
                        }
                        /* Reset baseline: old process accumulated bytes do not
                         * belong to the new process using this PID. */
                        g_states[i].prev_io_proc = cur_io_proc;
                    }
                }

                uint64_t d_io_proc = 0;
                if (cur_io_proc >= g_states[i].prev_io_proc) {
                    d_io_proc = cur_io_proc - g_states[i].prev_io_proc;
                }
                /* If cur_io_proc < prev_io_proc (PID reuse), d_io_proc stays 0 */
                /* Convert bytes/interval to bytes/sec */
                double io_freq = (slow_dt > 0) ? (double)d_io_proc / slow_dt : 0.0;
                g_states[i].prev_io_proc = cur_io_proc; 

                /* BPF io_counts still used for pairing with io_wait_ns (direct I/O) */
                uint64_t cur_io         = ebpf_tracer_read_io(&g_tracer, (uint32_t)pid);
                uint64_t d_io_wait_ns  = cur_io_wait_ns - g_states[i].prev_io_wait_ns;
                uint64_t d_io_for_wait = cur_io         - g_states[i].prev_io_count;

                /* io_wait_ms: avg latency per direct-I/O completion (BPF-measured).
                 * 0.0 for buffered I/O (not synchronously blocking the process).
                 * Clamp per-interval delta: BPF already clamps per-event at
                 * IO_WAIT_MAX_NS, but defence-in-depth against any bypass. */
                if (d_io_wait_ns > d_io_for_wait * IO_WAIT_MAX_NS)
                    d_io_wait_ns = d_io_for_wait * IO_WAIT_MAX_NS;
                double io_wait_ms = (d_io_for_wait > 0 && d_io_wait_ns > 0)
                                    ? (double)d_io_wait_ns / (double)d_io_for_wait / 1e6
                                    : 0.0;

                g_states[i].prev_io         = cur_io;
                g_states[i].prev_io_wait_ns = cur_io_wait_ns;
                g_states[i].prev_io_count   = cur_io;
                g_states[i].prev_rq_wait_ns = cur_rq_wait_ns;

                sw_push(&g_win_io     [i], io_freq);
                sw_push(&g_win_io_wait[i], io_wait_ms);

                /* ── CPU metrics — zero when process not on CPU ───────────
                 * ipc/llc/ctx/rq_wait are 0 when d_cycles==0.
                 * Classifier receives zeros and can treat them as idle.
                 * No skip — every monitored PID gets a ring buffer entry
                 * every interval so Bigyan sees the full picture. */
                double ipc      = (d_cycles > 0)
                                  ? (double)d_instr / (double)d_cycles : 0.0;
                double llc_rate = (d_cycles > 0 && d_instr > 0)
                                  ? (double)d_llc / (double)d_instr : 0.0;
                double ctx_freq = (double)d_ctx / slow_dt;
                /* rq_wait_ms: average milliseconds the process waited on the
                 * CPU runqueue per wakeup event.  Divide by d_ctx (number of
                 * voluntary context switches = wakeup events in this interval)
                 * NOT by slow_dt.  Dividing by slow_dt gives ms/second which
                 * is dimensionless and makes Prabhakar's "> 2ms" threshold
                 * meaningless.  Dividing by d_ctx gives the actual per-wakeup
                 * latency that the threshold was designed for. */
                /* Clamp per-interval delta: BPF already clamps per-event at
                 * RQ_WAIT_MAX_NS, but defence-in-depth against any bypass. */
                if (d_rq_wait_ns > (uint64_t)d_ctx * RQ_WAIT_MAX_NS)
                    d_rq_wait_ns = (uint64_t)d_ctx * RQ_WAIT_MAX_NS;
                double rq_wait_ms = (d_rq_wait_ns > 0 && d_ctx > 0)
                                    ? (double)d_rq_wait_ns / (double)d_ctx / 1e6
                                    : 0.0;

                sw_push(&g_win_ipc    [i], ipc);
                sw_push(&g_win_llc    [i], llc_rate);
                sw_push(&g_win_ctx    [i], ctx_freq);
                sw_push(&g_win_rq_wait[i], rq_wait_ms);

                /* ── CPU migration frequency ────────────────────────────────
                 * Read current cpu_id from BPF pid_last_cpu map.
                 * Count changes vs prev_cpu_id; divide by slow_dt → freq.
                 * prev_cpu_id == -1 on first interval: skip count so the
                 * baseline establishment doesn't register as a migration.
                 * Works regardless of --no-per-core (BPF only, no perf fd). */
                int cur_cpu_id = ebpf_tracer_read_last_cpu(&g_tracer, (uint32_t)pid);
                if (cur_cpu_id >= 0 && g_states[i].prev_cpu_id >= 0
                        && cur_cpu_id != g_states[i].prev_cpu_id) {
                    g_states[i].migration_count++;
                }
                double migration_freq = (slow_dt > 0)
                    ? (double)g_states[i].migration_count / slow_dt : 0.0;
                g_states[i].prev_cpu_id      = cur_cpu_id;
                g_states[i].migration_count  = 0;   /* reset for next interval */
                sw_push(&g_win_migration[i], migration_freq);

                /* Update aggregate cache for fast path */
                g_last_sm[i].pid                = pid;
                /* cpu_id on aggregate entry is always -1.
                 * Invariant: cpu_id == -1  ⟹  aggregate  ⟹  g_rb (classifier)
                 *            cpu_id >= 0   ⟹  per-core   ⟹  g_rb_sched (scheduler)
                 * Dashboard (g_rb_dash) receives both. */
                g_last_sm[i].cpu_id             = -1;
                g_last_sm[i].smoothed_ipc       = sw_mean(&g_win_ipc    [i]);
                g_last_sm[i].smoothed_llc_miss  = sw_mean(&g_win_llc    [i]);
                g_last_sm[i].smoothed_ctx_freq  = sw_mean(&g_win_ctx    [i]);
                g_last_sm[i].smoothed_io_freq   = sw_mean(&g_win_io     [i]);
                g_last_sm[i].smoothed_io_wait_ms= sw_mean(&g_win_io_wait[i]);
                g_last_sm[i].smoothed_rq_wait_ms= sw_mean(&g_win_rq_wait[i]);
                g_last_sm[i].smoothed_migration_freq = sw_mean(&g_win_migration[i]);

                if (sm_is_active(&g_last_sm[i])) {
                    g_last_sm_updated_ns[i] = now_ns;
                    g_last_sm_valid[i]      = true;

                    /* Aggregate → classifier + dashboard at slow-path cadence.
                     * Fast path also pushes aggregate to g_rb every 50ms. */
                    g_last_sm[i].timestamp_ns = now_ns;
                    if (g_rb)      rb_push(g_rb,      &g_last_sm[i]);
                    if (g_rb_dash) rb_push(g_rb_dash, &g_last_sm[i]);
                } else {
                    g_last_sm_valid[i] = false;
                }

                /* Per-core counters */
                if (g_cfg.per_core) {
                    for (int c = 0; c < g_ncores; c++) {
                        raw_counters_t cc;
                        if (perf_counter_read(&g_perf_pc[i][c], &cc) != 0)
                            continue;

                        uint64_t dc_cyc = cc.cycles       - g_core_prev[i][c].prev_cycles;
                        uint64_t dc_ins = cc.instructions - g_core_prev[i][c].prev_instr;
                        uint64_t dc_llc = cc.llc_misses   - g_core_prev[i][c].prev_llc;

                        g_core_prev[i][c].prev_cycles = cc.cycles;
                        g_core_prev[i][c].prev_instr  = cc.instructions;
                        g_core_prev[i][c].prev_llc    = cc.llc_misses;

                        if (dc_cyc == 0) continue;

                        double pc_ipc = (double)dc_ins / (double)dc_cyc;
                        double pc_llc = dc_ins > 0
                                        ? (double)dc_llc / (double)dc_ins : 0.0;

                        sw_push(&g_win_ipc_pc[i][c], pc_ipc);
                        sw_push(&g_win_llc_pc[i][c], pc_llc);

                        /* ctx/io signals are process-wide; copy from aggregate */
                        g_last_sm_pc[i][c].pid                = pid;
                        g_last_sm_pc[i][c].cpu_id             = c;
                        g_last_sm_pc[i][c].smoothed_ipc       = sw_mean(&g_win_ipc_pc[i][c]);
                        g_last_sm_pc[i][c].smoothed_llc_miss  = sw_mean(&g_win_llc_pc[i][c]);
                        g_last_sm_pc[i][c].smoothed_ctx_freq  = g_last_sm[i].smoothed_ctx_freq;
                        g_last_sm_pc[i][c].smoothed_io_freq   = g_last_sm[i].smoothed_io_freq;
                        g_last_sm_pc[i][c].smoothed_io_wait_ms= g_last_sm[i].smoothed_io_wait_ms;
                        g_last_sm_pc[i][c].smoothed_rq_wait_ms= g_last_sm[i].smoothed_rq_wait_ms;
                        g_last_sm_pc[i][c].smoothed_migration_freq = g_last_sm[i].smoothed_migration_freq;
                        g_last_sm_pc[i][c].timestamp_ns       = now_ns;

                        if (sm_is_active(&g_last_sm_pc[i][c])) {
                            /* Per-core → scheduler + dashboard.
                             * Never written to g_rb — classifier gets aggregate only. */
                            if (g_rb_sched) rb_push(g_rb_sched, &g_last_sm_pc[i][c]);
                            if (g_rb_dash)  rb_push(g_rb_dash,  &g_last_sm_pc[i][c]);
                        }

                        if (g_cfg.terminal_mode &&
                            (g_cfg.show_zero || sm_is_active(&g_last_sm_pc[i][c])))
                            printf("%-6d  %-4d  %-16s  %-7.3f  %-9.4f"
                                   "  %-9.1f  %-9.1f  %-10.2f  %-10.2f  %-10.2f\n",
                                   pid, c, "-",
                                   g_last_sm_pc[i][c].smoothed_ipc,
                                   g_last_sm_pc[i][c].smoothed_llc_miss,
                                   g_last_sm_pc[i][c].smoothed_ctx_freq,
                                   g_last_sm_pc[i][c].smoothed_io_freq,
                                   g_last_sm_pc[i][c].smoothed_io_wait_ms,
                                   g_last_sm_pc[i][c].smoothed_rq_wait_ms,
                                   g_last_sm_pc[i][c].smoothed_migration_freq);
                    }
                }

                /* CSV and terminal output are gated by display_limit.
                 * Ring buffer pushes happen for ALL active PIDs above. */
                if (displayed < display_limit) {
                if (g_csv) {
                    if (g_cfg.label)
                        fprintf(g_csv,
                                "%d,%" PRIu64 ",%.4f,%.6f,%.2f,%.2f,%.3f,%.3f,%.3f,%s\n",
                                pid, now_ns,
                                g_last_sm[i].smoothed_ipc,
                                g_last_sm[i].smoothed_llc_miss,
                                g_last_sm[i].smoothed_ctx_freq,
                                g_last_sm[i].smoothed_io_freq,
                                g_last_sm[i].smoothed_io_wait_ms,
                                g_last_sm[i].smoothed_rq_wait_ms,
                                g_last_sm[i].smoothed_migration_freq,
                                g_cfg.label);
                    else
                        fprintf(g_csv,
                                "%d,%" PRIu64 ",%.4f,%.6f,%.2f,%.2f,%.3f,%.3f,%.3f\n",
                                pid, now_ns,
                                g_last_sm[i].smoothed_ipc,
                                g_last_sm[i].smoothed_llc_miss,
                                g_last_sm[i].smoothed_ctx_freq,
                                g_last_sm[i].smoothed_io_freq,
                                g_last_sm[i].smoothed_io_wait_ms,
                                g_last_sm[i].smoothed_rq_wait_ms,
                                g_last_sm[i].smoothed_migration_freq);
                }

                /* Comm update: only refresh on exec (captured by BPF exec tracepoint).
                 * Calling read_proc_comm every 200ms is wasteful — comm almost never
                 * changes and the exec tracepoint fires immediately when it does. */
                ebpf_tracer_pop_exec_comm(&g_tracer, (uint32_t)pid,
                                          g_comm[i], sizeof(g_comm[i]));

                if (g_cfg.terminal_mode &&
                    (g_cfg.show_zero || sm_is_active(&g_last_sm[i])))
                    printf("%-6d  %-4s  %-16s  %-7.3f  %-9.4f"
                           "  %-9.1f  %-9.1f  %-10.2f  %-10.2f  %-10.2f\n",
                           pid, "agg", g_comm[i],
                           g_last_sm[i].smoothed_ipc,
                           g_last_sm[i].smoothed_llc_miss,
                           g_last_sm[i].smoothed_ctx_freq,
                           g_last_sm[i].smoothed_io_freq,
                           g_last_sm[i].smoothed_io_wait_ms,
                           g_last_sm[i].smoothed_rq_wait_ms,
                           g_last_sm[i].smoothed_migration_freq);

                displayed++;
                } /* end display_limit gate */
            }

            if (g_cfg.terminal_mode) { printf("----\n"); fflush(stdout); }
        } /* end slow path */

        /* ════════════════════════════════════════════════════════════
         * FAST PATH — every tick (50ms)
         * BUG2 FIX: only push entries that were updated within STALE_NS.
         * Sleeping processes stop appearing in the ring buffer after 1s,
         * which is correct — they are not running.
         * ════════════════════════════════════════════════════════════ */
        for (int i = 0; i < g_n_active; i++) {
            if (!g_last_sm_valid[i]) continue;
            if (now_ns - g_last_sm_updated_ns[i] > STALE_NS) continue;

            /* Fast path: push aggregate to classifier at 50ms cadence */
            g_last_sm[i].timestamp_ns = now_ns;
            rb_push(g_rb, &g_last_sm[i]);

            if (g_cfg.per_core) {
                for (int c = 0; c < g_ncores; c++) {
                    if (g_last_sm_pc[i][c].pid == 0) continue;
                    if (now_ns - g_last_sm_updated_ns[i] > STALE_NS) continue;
                    /* Fast path: push per-core to scheduler at 50ms cadence.
                     * Never to g_rb — classifier gets aggregate only. */
                    g_last_sm_pc[i][c].timestamp_ns = now_ns;
                    if (g_rb_sched) rb_push(g_rb_sched, &g_last_sm_pc[i][c]);
                }
            }
        }

        /* Absolute-deadline sleep — no drift */
        long interval_ns = (long)g_cfg.interval_ms * 1000000L;
        struct timespec deadline = {
            .tv_sec  = t_start.tv_sec  + interval_ns / 1000000000L,
            .tv_nsec = t_start.tv_nsec + interval_ns % 1000000000L,
        };
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec  += 1;
            deadline.tv_nsec -= 1000000000L;
        }
        int sleep_ret = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &deadline, NULL);
        if (sleep_ret == EINTR && !g_running)
            break;   /* SIGTERM/SIGINT received — exit the loop cleanly */
        sample_num = (sample_num + 1) % 4;  /* fix #13: no 3.4-year overflow */
    }
}

/* ── cleanup ────────────────────────────────────────────────────────────── */

static void cleanup(void) {
    for (int i = 0; i < g_n_active; i++) {
        if (g_states[i].io_fd >= 0) {
            close(g_states[i].io_fd);
            g_states[i].io_fd = -1;
        }
        perf_counter_close(&g_perf[i]);
        if (g_cfg.per_core)
            for (int c = 0; c < g_ncores; c++)
                perf_counter_close(&g_perf_pc[i][c]);
    }
    ebpf_tracer_destroy(&g_tracer);
    if (g_rb)       rb_destroy(g_rb);
    if (g_rb_dash)  rb_destroy_dash(g_rb_dash);
    if (g_rb_sched) rb_destroy_sched(g_rb_sched);
    if (g_csv)      fclose(g_csv);
    printf("[daemon] Clean shutdown.\n");
}

/* ── main ───────────────────────────────────────────────────────────────── */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <bpf.o> [OPTIONS]\n\n"
            "Options:\n"
            "  --top N          Display top N processes (default: all tracked)\n"
            "                   Note: ALL tracked processes get metrics computed.\n"
            "                   --top only limits terminal/CSV output.\n"
            "  --pids P1,P2     Monitor specific PIDs explicitly\n"
            "  --interval MS    Sample interval ms (default: %d)\n"
            "  --csv FILE       Write samples to CSV\n"
            "  --label STR      Workload label written to CSV (calibration)\n"
            "  --min-uid UID    Min UID to include (default: 0 = all incl. root)\n"
            "  --no-per-core    Disable per-core counters (for VMs)\n"
            "  --no-shm         Skip ring buffer creation (CSV-only/calibration mode)\n"
            "  --zero, -z       Show zero-value processes in terminal output\n"
            "  --terminal       Enable stdout output (manual use)\n\n"
            "Defaults: all processes (uid >= 0), per-core ON.\n"
            "Use --no-per-core on VMs without hardware PMU.\n\n"
            "Examples:\n"
            "  sudo %s /opt/schedmon/bpf/ctx_switch.bpf.o --top 5 --terminal\n"
            "  sudo %s /opt/schedmon/bpf/ctx_switch.bpf.o --csv out.csv\n"
            "  sudo %s /opt/schedmon/bpf/ctx_switch.bpf.o --pids 1234,5678 --terminal\n",
            argv[0], DEFAULT_INTERVAL,
            argv[0], argv[0], argv[0]);
        exit(1);
    }

    const char *bpf_path = argv[1];
    parse_args(argc - 2, argv + 2);
    g_running = 1;
    g_cfg.running = true;

    signal(SIGTERM, handle_signal);
    signal(SIGINT,  handle_signal);

    g_ncores = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (g_ncores <= 0) {
        fprintf(stderr, "[daemon] sysconf(_SC_NPROCESSORS_ONLN) failed — defaulting to 2\n");
        g_ncores = 2;
    } else if (g_ncores > MAX_CORES) {
        fprintf(stderr, "[daemon] WARNING: %d cores detected, clamping to MAX_CORES=%d\n",
                g_ncores, MAX_CORES);
        g_ncores = MAX_CORES;
    }

    printf("[daemon] ABI version %d  |  %d cores  |  per-core: %s\n",
           MONITOR_ABI_VERSION, g_ncores,
           g_cfg.per_core ? "ON" : "OFF (--no-per-core)");

    proc_scanner_init(&g_scanner);
    init_ebpf(bpf_path);
    init_shm();
    check_proc_io_access();

    if (g_cfg.csv_path) {
        g_csv = fopen(g_cfg.csv_path, "w");
        if (!g_csv) { perror("fopen csv"); exit(1); }
        /* Issue 8 fix: line-buffer so data survives crashes */
        setvbuf(g_csv, NULL, _IOLBF, 0);
        /* Header: label column present only when --label was supplied.
         * Bigyan's classifier reads the CSV; consistent header means no
         * special-casing needed on his side — label is simply absent when
         * the daemon runs in production (non-calibration) mode. */
        if (g_cfg.label)
            fprintf(g_csv,
                    "pid,timestamp_ns,ipc,llc_miss,ctx_freq,"
                    "io_freq,io_wait_ms,rq_wait_ms,migration_freq,label\n");
        else
            fprintf(g_csv,
                    "pid,timestamp_ns,ipc,llc_miss,ctx_freq,"
                    "io_freq,io_wait_ms,rq_wait_ms,migration_freq\n");
    }

    if (g_cfg.n_pids > 0)
        printf("[daemon] Explicit PID mode: %d PIDs\n", g_cfg.n_pids);
    else
        printf("[daemon] Top-%d mode (uid >= %d), interval=%dms\n",
               g_cfg.top_n, g_cfg.min_uid, g_cfg.interval_ms);

    run_sampling_loop();
    cleanup();
    return 0;
}
