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
#include <sys/resource.h>
#include <errno.h>
#include "perf_counter.h"
#include "ebpf_tracer.h"
#include "sliding_window.h"
#include "ring_buffer.h"
#include "smoothed_metrics.h"
#include "proc_scanner.h"
#include "schedmon.h"

/* stale after 1 sec, 5x the 200ms slow path interval */
#define STALE_NS          1000000000ULL

/* sanity clamps for corrupted timestamps */
#define RQ_WAIT_MAX_NS    10000000000ULL
#define IO_WAIT_MAX_NS    30000000000ULL

#define LINUX_PID_MAX     4194304

static DaemonConfig   g_cfg;
static PidState       g_states [MAX_PIDS];
static SlidingWindow  g_win_ipc[MAX_PIDS];
static SlidingWindow  g_win_llc[MAX_PIDS];
static SlidingWindow  g_win_ctx[MAX_PIDS];
static SlidingWindow  g_win_io [MAX_PIDS];
static SlidingWindow  g_win_io_wait[MAX_PIDS];
static SlidingWindow  g_win_rq_wait[MAX_PIDS];
static SlidingWindow  g_win_migration[MAX_PIDS];
static SlidingWindow  g_win_io_syscall[MAX_PIDS];

static perf_counter_t g_perf   [MAX_PIDS];

/* slow path (200ms) fills these, fast path (50ms) just stamps a new
 * timestamp and pushes to the ring buffers. fast path skips anything
 * not touched within STALE_NS or a sleeping process would keep showing
 * up as active with a fresh timestamp forever */
static SmoothedMetrics g_last_sm   [MAX_PIDS];
static uint64_t        g_last_sm_updated_ns[MAX_PIDS];
static bool            g_last_sm_valid     [MAX_PIDS];
static char            g_comm      [MAX_PIDS][17];

static int            g_ncores  = 0;
static ebpf_tracer_t  g_tracer;
static RingBuffer    *g_rb      = NULL;
static RingBuffer    *g_rb_dash = NULL;
static FILE          *g_csv     = NULL;
static int            g_n_active = 0;
static ProcScanner    g_scanner;

static volatile sig_atomic_t g_running = 0;
static void handle_signal(int sig) { (void)sig; g_running = 0; }

/* keep the fd open instead of fopen/fclose every read, way faster at
 * 256 pids x 200ms. reads /proc/pid/io which attributes io correctly
 * even for writeback (unlike bpf block_rq_issue which runs in kworker
 * ctx for that case) */
#define PROC_IO_READ_FAIL  UINT64_MAX

/* returns physical disk bytes (read+write-cancelled). also fills
 * out_syscall_bytes with rchar+wchar if it succeeds -- these two
 * numbers measure different things (disk vs syscall traffic incl
 * cache hits) so dont merge them */
static uint64_t read_proc_io_fd(int fd, uint64_t *out_syscall_bytes) {
    if (fd < 0) return PROC_IO_READ_FAIL;

    /* Widened from 256: /proc/PID/io now has 7 lines scanned (rchar, wchar,
     * syscr, syscw, read_bytes, write_bytes, cancelled_write_bytes) and the
     * worst case with full-width uint64 values on every line was already
     * close to the old 256-byte limit before rchar/wchar were added. */
    char buf[512];
    if (lseek(fd, 0, SEEK_SET) < 0) return PROC_IO_READ_FAIL;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0) return PROC_IO_READ_FAIL;
    buf[n] = '\0';

    uint64_t read_bytes = 0, write_bytes = 0, cancelled = 0;
    uint64_t rchar = 0, wchar = 0;
    char *p = buf;
    while (*p) {
        /* Check the longer/more-specific prefixes first: "rchar:"/"wchar:"
         * are themselves unambiguous, but keep ordering consistent with
         * the existing read_bytes/write_bytes/cancelled_write_bytes checks
         * below (cancelled_write_bytes must be checked before write_bytes
         * would ever be a prefix issue — it isn't here, but keep the same
         * defensive style). */
        if (strncmp(p, "rchar:", 6) == 0)
            rchar = strtoull(p + 6, NULL, 10);
        else if (strncmp(p, "wchar:", 6) == 0)
            wchar = strtoull(p + 6, NULL, 10);
        else if (strncmp(p, "read_bytes:", 11) == 0)
            read_bytes = strtoull(p + 11, NULL, 10);
        else if (strncmp(p, "write_bytes:", 12) == 0)
            write_bytes = strtoull(p + 12, NULL, 10);
        else if (strncmp(p, "cancelled_write_bytes:", 22) == 0)
            cancelled = strtoull(p + 22, NULL, 10);
        /* advance to next line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }

    if (out_syscall_bytes) *out_syscall_bytes = rchar + wchar;

    uint64_t total = read_bytes + write_bytes;
    return (total >= cancelled) ? (total - cancelled) : 0;
}

static int g_io_fd_fail_count = 0;
static int g_io_fd_ok_count   = 0;

static int open_proc_io_fd(int pid) {
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/io", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        g_io_fd_fail_count++;
        /* only log first + every 50th so we dont flood the journal */
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

static void parse_args(int argc, char **argv) {
    g_cfg.interval_ms   = DEFAULT_INTERVAL;
    g_cfg.terminal_mode = false;
    g_cfg.n_pids        = 0;
    g_cfg.top_n         = 0;
    g_cfg.min_uid       = MIN_UID;
    g_cfg.csv_path      = NULL;
    g_cfg.label         = NULL;
    g_cfg.show_zero     = false;

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
        } else if (strcmp(argv[i], "--label") == 0 && i + 1 < argc) {
            /* label gets written into the csv, used for calibration */
            g_cfg.label = argv[++i];
        } else if (strcmp(argv[i], "--terminal") == 0) {
            g_cfg.terminal_mode = true;
        } else if (strcmp(argv[i], "--zero") == 0 ||
                   strcmp(argv[i], "-z") == 0) {
            /* just for terminal display, ring buffer never gets zeros anyway */
            g_cfg.show_zero = true;
        }
    }

    if (g_cfg.n_pids == 0 && g_cfg.top_n == 0)
        g_cfg.top_n = DEFAULT_TOP_N;
}

static int find_slot(int pid) {
    for (int i = 0; i < g_n_active; i++)
        if (g_states[i].pid == pid) return i;
    return -1;
}

static int add_pid(int pid) {
    if (g_n_active >= MAX_PIDS) return -1;
    int i = g_n_active;

    memset(&g_perf[i], 0, sizeof(g_perf[i]));
    g_perf[i].fd_cycles = g_perf[i].fd_instr = g_perf[i].fd_llc = -1;

    if (perf_counter_open(&g_perf[i], (pid_t)pid, -1) != 0) {
        fprintf(stderr, "[daemon] perf_counter_open failed for PID %d\n", pid);
        perf_counter_close(&g_perf[i]);
        return -1;
    }

    memset(&g_states[i],     0, sizeof(g_states[i]));
    memset(&g_last_sm[i],    0, sizeof(g_last_sm[i]));
    g_states[i].io_fd         = -1;
    g_states[i].prev_cpu_id   = -1;
    g_states[i].migration_count = 0;
    g_comm[i][0]              = '\0';
    g_last_sm_valid[i]        = false;
    g_last_sm_updated_ns[i]   = 0;

    g_states[i].pid    = pid;
    g_states[i].active = 1;
    sw_init(&g_win_ipc[i]);
    sw_init(&g_win_llc[i]);
    sw_init(&g_win_ctx[i]);
    sw_init(&g_win_io[i]);
    sw_init(&g_win_io_wait[i]);
    sw_init(&g_win_rq_wait[i]);
    sw_init(&g_win_migration[i]);
    sw_init(&g_win_io_syscall[i]);

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
    g_states[i].io_fd = open_proc_io_fd(pid);
    if (g_states[i].io_fd >= 0) {
        uint64_t seed_syscall = 0;
        uint64_t seed_io = read_proc_io_fd(g_states[i].io_fd, &seed_syscall);
        g_states[i].prev_io_proc    = (seed_io == PROC_IO_READ_FAIL) ? 0 : seed_io;
        g_states[i].prev_io_syscall = (seed_io == PROC_IO_READ_FAIL) ? 0 : seed_syscall;
    } else {
        g_states[i].prev_io_proc    = 0;
        g_states[i].prev_io_syscall = 0;
    }

    if (!ebpf_tracer_pop_exec_comm(&g_tracer, (uint32_t)pid,
                                   g_comm[i], sizeof(g_comm[i])))
        read_proc_comm(pid, g_comm[i], sizeof(g_comm[i]));

    ebpf_tracer_register_pid(&g_tracer, (uint32_t)pid);

    g_n_active++;
    return i;
}

static void remove_slot(int i) {
    ebpf_tracer_unregister_pid(&g_tracer, (uint32_t)g_states[i].pid);

    if (g_states[i].io_fd >= 0) {
        close(g_states[i].io_fd);
        g_states[i].io_fd = -1;
    }

    perf_counter_close(&g_perf[i]);

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
        g_win_io_syscall   [i] = g_win_io_syscall   [last];
        g_perf             [i] = g_perf             [last];
        g_last_sm          [i] = g_last_sm          [last];
        g_last_sm_valid    [i] = g_last_sm_valid    [last];
        g_last_sm_updated_ns[i]= g_last_sm_updated_ns[last];
        memcpy(g_comm[i],         g_comm[last],         sizeof(g_comm[i]));
    }
    /* clear last slot so next add_pid there starts clean */
    g_last_sm_valid    [last] = false;
    g_last_sm_updated_ns[last] = 0;
    g_n_active--;
}

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

    if (g_cfg.n_pids == 0) {
        proc_scanner_scan(&g_scanner);
    } else {
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
    /* calibrate.py stops the systemd daemon during its measurement windows
     * so theres never two writers on these at once */
    g_rb = rb_create();
    if (!g_rb) { fprintf(stderr, "[daemon] FATAL: cannot create shm\n"); exit(1); }
    g_rb_dash = rb_create_dash();
    if (!g_rb_dash) { fprintf(stderr, "[daemon] FATAL: cannot create dash shm\n"); exit(1); }
    printf("[daemon] Ring buffers ready: %s  %s\n", SHM_NAME, SHM_NAME_DASH);
}

/* checks /proc/pid/io is actually readable. needs CAP_SYS_PTRACE even as
 * root under systemd with NoNewPrivileges, CAP_DAC_READ_SEARCH alone isnt
 * enough. just warns, doesnt exit -- io_freq is 0 if this fails */
static void check_proc_io_access(void) {
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

/* true if any metric is nonzero, used to skip pushing all-zero rows into
 * the ring buffer so the classifier isnt fed noise. --zero shows them
 * in terminal mode anyway */
static inline bool sm_is_active(const SmoothedMetrics *m) {
    return m->smoothed_ipc       > 0.0
        || m->smoothed_llc_miss  > 0.0
        || m->smoothed_ctx_freq  > 0.0
        || m->smoothed_io_freq   > 0.0
        || m->smoothed_io_wait_ms > 0.0
        || m->smoothed_rq_wait_ms > 0.0
        || m->smoothed_migration_freq > 0.0
        || m->smoothed_io_syscall_freq > 0.0;
}

static void run_sampling_loop(void) {
    int sample_num = 0;
    int first_slow = 1;
    struct timespec last_slow = {0,0};
    clock_gettime(CLOCK_MONOTONIC, &last_slow);

    if (g_cfg.terminal_mode)
        printf("%-6s  %-4s  %-16s  %-7s  %-9s  %-9s  %-9s  %-10s  %-10s  %-10s\n",
               "PID", "CORE", "COMM",
               "IPC", "LLC%", "ctx/s", "io/s", "io_wait_ms", "rq_wait_ms", "mig/s");

    while (g_running) {
        struct timespec t_start;
        clock_gettime(CLOCK_MONOTONIC, &t_start);
        uint64_t now_ns = (uint64_t)t_start.tv_sec * 1000000000ULL
                        + (uint64_t)t_start.tv_nsec;

        /* slow path runs every 4th tick, 200ms */
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

            /* display_limit only affects terminal output, we still have to
             * drain every active slot's perf fds every interval or the
             * counters pile up and the next delta gets inflated */
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

                /* pid reuse can make bpf counters go backwards, reset and
                 * skip this interval if that happens */
                if (cur_ctx        < g_states[i].prev_ctx        ||
                    cur_io_wait_ns < g_states[i].prev_io_wait_ns ||
                    cur_rq_wait_ns < g_states[i].prev_rq_wait_ns) {
                    g_states[i].prev_ctx        = cur_ctx;
                    g_states[i].prev_io_wait_ns = cur_io_wait_ns;
                    g_states[i].prev_rq_wait_ns = cur_rq_wait_ns;
                    g_states[i].prev_cycles       = cur_hw.cycles;
                    g_states[i].prev_instructions = cur_hw.instructions;
                    g_states[i].prev_llc          = cur_hw.llc_misses;
                    continue;
                }

                uint64_t d_cycles = cur_hw.cycles       - g_states[i].prev_cycles;
                uint64_t d_instr  = cur_hw.instructions - g_states[i].prev_instructions;
                uint64_t d_llc    = cur_hw.llc_misses   - g_states[i].prev_llc;

                /* same deal but for the hw counters, can wrap/reset too */
                if (cur_hw.cycles < g_states[i].prev_cycles) {
                    g_states[i].prev_cycles       = cur_hw.cycles;
                    g_states[i].prev_instructions = cur_hw.instructions;
                    g_states[i].prev_llc          = cur_hw.llc_misses;
                    g_states[i].prev_ctx        = cur_ctx;
                    g_states[i].prev_io_wait_ns = cur_io_wait_ns;
                    g_states[i].prev_rq_wait_ns = cur_rq_wait_ns;
                    continue;
                }
                uint64_t d_ctx    = cur_ctx              - g_states[i].prev_ctx;

                /* avg wait ms per wakeup event */
                uint64_t d_rq_wait_ns = cur_rq_wait_ns - g_states[i].prev_rq_wait_ns;

                g_states[i].prev_cycles       = cur_hw.cycles;
                g_states[i].prev_instructions = cur_hw.instructions;
                g_states[i].prev_llc          = cur_hw.llc_misses;
                g_states[i].prev_ctx = cur_ctx;

                if (g_last_sm[i].pid == 0) {
                    g_last_sm[i].pid    = pid;
                    g_last_sm[i].cpu_id = -1;
                }

                /* io_freq comes from /proc/pid/io read+write bytes, gets the
                 * process right even for writeback io which bpf block_rq
                 * would attribute to kworker instead. io_syscall_freq is
                 * rchar+wchar from the same file, different signal, includes
                 * cache hits with no real disk activity so keep separate.
                 * io_wait_ms stays bpf-only, only meaningful for direct io */
                uint64_t cur_io_proc    = 0;
                uint64_t cur_io_syscall = 0;
                if (g_states[i].io_fd >= 0) {
                    cur_io_proc = read_proc_io_fd(g_states[i].io_fd, &cur_io_syscall);

                    /* read fail means stale fd (proc exited/pid reused), not
                     * that it did zero io, so only reopen on actual failure */
                    if (cur_io_proc == PROC_IO_READ_FAIL) {
                        close(g_states[i].io_fd);
                        g_states[i].io_fd = open_proc_io_fd(g_states[i].pid);
                        if (g_states[i].io_fd >= 0) {
                            cur_io_proc = read_proc_io_fd(g_states[i].io_fd, &cur_io_syscall);
                            if (cur_io_proc == PROC_IO_READ_FAIL) {
                                cur_io_proc    = 0;
                                cur_io_syscall = 0;
                            }
                        } else {
                            cur_io_proc    = 0;
                            cur_io_syscall = 0;
                        }
                        g_states[i].prev_io_proc    = cur_io_proc;
                        g_states[i].prev_io_syscall = cur_io_syscall;
                    }
                }

                uint64_t d_io_proc = 0;
                if (cur_io_proc >= g_states[i].prev_io_proc) {
                    d_io_proc = cur_io_proc - g_states[i].prev_io_proc;
                }
                double io_freq = (slow_dt > 0) ? (double)d_io_proc / slow_dt : 0.0;
                g_states[i].prev_io_proc = cur_io_proc; 

                uint64_t d_io_syscall = 0;
                if (cur_io_syscall >= g_states[i].prev_io_syscall) {
                    d_io_syscall = cur_io_syscall - g_states[i].prev_io_syscall;
                }
                double io_syscall_freq = (slow_dt > 0) ? (double)d_io_syscall / slow_dt : 0.0;
                g_states[i].prev_io_syscall = cur_io_syscall;

                uint64_t cur_io         = ebpf_tracer_read_io(&g_tracer, (uint32_t)pid);
                uint64_t d_io_wait_ns  = cur_io_wait_ns - g_states[i].prev_io_wait_ns;
                uint64_t d_io_for_wait = cur_io         - g_states[i].prev_io_count;

                /* clamp again here even though bpf side already clamps per event */
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
                sw_push(&g_win_io_syscall[i], io_syscall_freq);

                /* these all stay 0 if d_cycles is 0, thats fine, classifier
                 * treats that as idle. still push every interval so every
                 * pid gets a ring buffer entry */
                double ipc      = (d_cycles > 0)
                                  ? (double)d_instr / (double)d_cycles : 0.0;
                double llc_rate = (d_cycles > 0 && d_instr > 0)
                                  ? (double)d_llc / (double)d_instr : 0.0;
                double ctx_freq = (double)d_ctx / slow_dt;
                /* divide by d_ctx not slow_dt, we want ms per wakeup not
                 * ms per second */
                if (d_rq_wait_ns > (uint64_t)d_ctx * RQ_WAIT_MAX_NS)
                    d_rq_wait_ns = (uint64_t)d_ctx * RQ_WAIT_MAX_NS;
                double rq_wait_ms = (d_rq_wait_ns > 0 && d_ctx > 0)
                                    ? (double)d_rq_wait_ns / (double)d_ctx / 1e6
                                    : 0.0;

                sw_push(&g_win_ipc    [i], ipc);
                sw_push(&g_win_llc    [i], llc_rate);
                sw_push(&g_win_ctx    [i], ctx_freq);
                sw_push(&g_win_rq_wait[i], rq_wait_ms);

                /* prev_cpu_id -1 on first interval so we dont count the
                 * initial baseline as a migration */
                int cur_cpu_id = ebpf_tracer_read_last_cpu(&g_tracer, (uint32_t)pid);
                if (cur_cpu_id >= 0 && g_states[i].prev_cpu_id >= 0
                        && cur_cpu_id != g_states[i].prev_cpu_id) {
                    g_states[i].migration_count++;
                }
                double migration_freq = (slow_dt > 0)
                    ? (double)g_states[i].migration_count / slow_dt : 0.0;
                g_states[i].prev_cpu_id      = cur_cpu_id;
                g_states[i].migration_count  = 0;
                sw_push(&g_win_migration[i], migration_freq);

                g_last_sm[i].pid                = pid;
                /* cpu_id always -1 now, per core tracking got dropped since
                 * none of the schedulers we target need it. keeping the
                 * field around anyway in case that changes later */
                g_last_sm[i].cpu_id             = -1;
                /* if 0, ipc/llc_miss below are always 0 because software
                 * fallback cant count instructions, dont read that as idle */
                g_last_sm[i].hw_pmu_available    = g_perf[i].hw_available;
                g_last_sm[i].smoothed_ipc       = sw_mean(&g_win_ipc    [i]);
                g_last_sm[i].smoothed_llc_miss  = sw_mean(&g_win_llc    [i]);
                g_last_sm[i].smoothed_ctx_freq  = sw_mean(&g_win_ctx    [i]);
                g_last_sm[i].smoothed_io_freq   = sw_mean(&g_win_io     [i]);
                g_last_sm[i].smoothed_io_wait_ms= sw_mean(&g_win_io_wait[i]);
                g_last_sm[i].smoothed_rq_wait_ms= sw_mean(&g_win_rq_wait[i]);
                g_last_sm[i].smoothed_migration_freq = sw_mean(&g_win_migration[i]);
                g_last_sm[i].smoothed_io_syscall_freq = sw_mean(&g_win_io_syscall[i]);

                if (sm_is_active(&g_last_sm[i])) {
                    g_last_sm_updated_ns[i] = now_ns;
                    g_last_sm_valid[i]      = true;

                    g_last_sm[i].timestamp_ns = now_ns;
                    if (g_rb)      rb_push(g_rb,      &g_last_sm[i]);
                    if (g_rb_dash) rb_push(g_rb_dash, &g_last_sm[i]);
                } else {
                    g_last_sm_valid[i] = false;
                }

                /* csv/terminal respect display_limit, ring buffer push happens
                 * for everything above regardless */
                if (displayed < display_limit) {
                if (g_csv) {
                    if (g_cfg.label)
                        fprintf(g_csv,
                                "%d,%" PRIu64 ",%.4f,%.6f,%.2f,%.2f,%.3f,%.3f,%.3f,%.2f,%s\n",
                                pid, now_ns,
                                g_last_sm[i].smoothed_ipc,
                                g_last_sm[i].smoothed_llc_miss,
                                g_last_sm[i].smoothed_ctx_freq,
                                g_last_sm[i].smoothed_io_freq,
                                g_last_sm[i].smoothed_io_wait_ms,
                                g_last_sm[i].smoothed_rq_wait_ms,
                                g_last_sm[i].smoothed_migration_freq,
                                g_last_sm[i].smoothed_io_syscall_freq,
                                g_cfg.label);
                    else
                        fprintf(g_csv,
                                "%d,%" PRIu64 ",%.4f,%.6f,%.2f,%.2f,%.3f,%.3f,%.3f,%.2f\n",
                                pid, now_ns,
                                g_last_sm[i].smoothed_ipc,
                                g_last_sm[i].smoothed_llc_miss,
                                g_last_sm[i].smoothed_ctx_freq,
                                g_last_sm[i].smoothed_io_freq,
                                g_last_sm[i].smoothed_io_wait_ms,
                                g_last_sm[i].smoothed_rq_wait_ms,
                                g_last_sm[i].smoothed_migration_freq,
                                g_last_sm[i].smoothed_io_syscall_freq);
                }

                /* only refresh comm on exec, no point doing it every tick */
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
                }
            }

            if (g_cfg.terminal_mode) { printf("----\n"); fflush(stdout); }
        }

        /* fast path, every tick (50ms). skip stale entries so sleeping
         * processes drop out of the ring buffer after ~1s instead of
         * showing fresh timestamps forever */
        for (int i = 0; i < g_n_active; i++) {
            if (!g_last_sm_valid[i]) continue;
            if (now_ns - g_last_sm_updated_ns[i] > STALE_NS) continue;

            g_last_sm[i].timestamp_ns = now_ns;
            if (g_rb) rb_push(g_rb, &g_last_sm[i]);
        }

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
            break;
        sample_num = (sample_num + 1) % 4;
    }
}

static void cleanup(void) {
    for (int i = 0; i < g_n_active; i++) {
        if (g_states[i].io_fd >= 0) {
            close(g_states[i].io_fd);
            g_states[i].io_fd = -1;
        }
        perf_counter_close(&g_perf[i]);
    }
    ebpf_tracer_destroy(&g_tracer);
    if (g_rb)       rb_destroy(g_rb);
    if (g_rb_dash)  rb_destroy_dash(g_rb_dash);
    if (g_csv)      fclose(g_csv);
    printf("[daemon] Clean shutdown.\n");
}

/* tracking a lot of pids can blow past the default 1024 fd limit even
 * without per core stuff. rough estimate is 3 perf fds + 1 io fd per pid,
 * doubled for bpf links/map fds/shm/etc that arent itemized here.
 * schedmon.service sets LimitNOFILE=65536 but a manually run daemon has
 * no such help, so try to raise it ourselves at startup. raising soft up
 * to hard doesnt need any special privilege */
static void raise_fd_limit(void) {
    int max_pids = (g_cfg.n_pids > 0) ? g_cfg.n_pids
                 : (g_cfg.top_n  > 0) ? g_cfg.top_n : DEFAULT_TOP_N;

    long fds_per_pid = 3 + 1;
    long raw_estimate = (long)max_pids * fds_per_pid + 64;
    long estimated = raw_estimate * 2;

    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        fprintf(stderr, "[daemon] WARNING: getrlimit(RLIMIT_NOFILE) failed: %s"
                        " — cannot check/raise fd limit\n", strerror(errno));
        return;
    }

    printf("[daemon] fd budget: estimated ~%ld fds needed (%d PIDs), "
           "current limit soft=%lld hard=%lld\n",
           estimated, max_pids, (long long)rl.rlim_cur, (long long)rl.rlim_max);

    if ((rlim_t)estimated <= rl.rlim_cur) {
        return;
    }

    rlim_t target = (rl.rlim_max == RLIM_INFINITY)
                   ? (rlim_t)estimated
                   : rl.rlim_max;

    struct rlimit new_rl = { .rlim_cur = target, .rlim_max = rl.rlim_max };
    if (setrlimit(RLIMIT_NOFILE, &new_rl) == 0) {
        printf("[daemon] Raised fd soft limit %lld -> %lld to cover estimated need\n",
               (long long)rl.rlim_cur, (long long)target);
        if ((rlim_t)estimated > target) {
            fprintf(stderr, "[daemon] WARNING: even the raised limit (%lld) is below the "
                            "estimated need (%ld) — the hard limit itself is the "
                            "constraint here. Some PIDs may still fail to open perf "
                            "counters under full load; see LimitNOFILE= in "
                            "schedmon.service if running under systemd, or raise the "
                            "hard limit (root/CAP_SYS_RESOURCE required) otherwise.\n",
                    (long long)target, estimated);
        }
    } else {
        fprintf(stderr, "[daemon] WARNING: setrlimit(RLIMIT_NOFILE) failed: %s"
                        " — estimated need is ~%ld fds but soft limit stays at %lld. "
                        "Some PIDs may fail to open perf counters under full load; "
                        "run 'ulimit -n %ld' before starting, or raise LimitNOFILE= "
                        "in schedmon.service if running under systemd.\n",
                strerror(errno), estimated, (long long)rl.rlim_cur, estimated);
    }
}

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
            "  --zero, -z       Show zero-value processes in terminal output\n"
            "  --terminal       Enable stdout output (manual use)\n\n"
            "Defaults: all processes (uid >= 0).\n\n"
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
    }

    printf("[daemon] ABI version %d  |  %d cores detected (aggregate-only monitoring)\n",
           MONITOR_ABI_VERSION, g_ncores);

    raise_fd_limit();

    proc_scanner_init(&g_scanner);
    init_ebpf(bpf_path);
    init_shm();
    check_proc_io_access();

    if (g_cfg.csv_path) {
        g_csv = fopen(g_cfg.csv_path, "w");
        if (!g_csv) { perror("fopen csv"); exit(1); }
        setvbuf(g_csv, NULL, _IOLBF, 0);
        /* label column only when --label is passed, keeps header consistent
         * either way so the classifier side doesnt need special casing */
        if (g_cfg.label)
            fprintf(g_csv,
                    "pid,timestamp_ns,ipc,llc_miss,ctx_freq,"
                    "io_freq,io_wait_ms,rq_wait_ms,migration_freq,io_syscall_freq,label\n");
        else
            fprintf(g_csv,
                    "pid,timestamp_ns,ipc,llc_miss,ctx_freq,"
                    "io_freq,io_wait_ms,rq_wait_ms,migration_freq,io_syscall_freq\n");
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