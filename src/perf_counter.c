#include "perf_counter.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>

/* Grouped read buffer — same layout as perf_grouped.c */
struct read_format {
    uint64_t nr;
    struct { uint64_t value; uint64_t id; } values[3];
};

static long perf_event_open(struct perf_event_attr *hw_event,
                             pid_t pid, int cpu, int group_fd,
                             unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static int open_counter(uint32_t type, uint64_t config,
                        pid_t pid, int cpu_id, int leader_fd) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type       = type;
    pe.size       = sizeof(pe);
    pe.config     = config;
    pe.disabled   = 1;
    pe.exclude_hv = 1;
    if (leader_fd == -1)
        pe.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
    /* cpu_id=-1: follow process anywhere; >=0: pin to that core */
    int fd = perf_event_open(&pe, pid, cpu_id, leader_fd, 0);
    if (fd == -1) {
        fprintf(stderr, "perf_counter: open_counter failed (cpu=%d): %s\n",
                cpu_id, strerror(errno));
    }
    return fd;
}

int perf_counter_open(perf_counter_t *pc, pid_t pid, int cpu_id) {
    memset(pc, 0, sizeof(*pc));
    pc->pid    = pid;
    pc->cpu_id = cpu_id;   /* -1 = aggregate, >=0 = pinned core */
    pc->fd_cycles = pc->fd_instr = pc->fd_llc = -1;
    pc->hw_available = 1;  /* assume hardware until proven otherwise */

    pc->fd_cycles = open_counter(PERF_TYPE_HARDWARE,
                                 PERF_COUNT_HW_CPU_CYCLES, pid, cpu_id, -1);
    if (pc->fd_cycles < 0) {
        /* Hardware PMU unavailable (VM, privilege, no PMU).
         * Fall back to PERF_TYPE_SOFTWARE so the daemon can still run.
         * IPC cannot be computed without real instruction counts —
         * smoothed_ipc will be reported as 0.0 in degraded mode.
         * smoothed_llc_miss will also be 0.0 (no LLC counter available).
         * smoothed_ctx_freq and smoothed_io_freq are unaffected (eBPF). */
        fprintf(stderr, "perf_counter: hardware PMU unavailable for pid=%d"
                        " — falling back to software clock counter\n", (int)pid);
        pc->hw_available = 0;

        pc->fd_cycles = open_counter(PERF_TYPE_SOFTWARE,
                                     PERF_COUNT_SW_CPU_CLOCK, pid, cpu_id, -1);
        if (pc->fd_cycles < 0) {
            fprintf(stderr, "perf_counter: software fallback also failed"
                            " for pid=%d\n", (int)pid);
            return -1;
        }
        /* In software-only mode we only have the clock counter — no instr
         * or LLC fd.  Leave them at -1; perf_counter_read handles this. */
        ioctl(pc->fd_cycles, PERF_EVENT_IOC_RESET,  0);
        ioctl(pc->fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
        return 0;
    }

    pc->fd_instr  = open_counter(PERF_TYPE_HARDWARE,
                                 PERF_COUNT_HW_INSTRUCTIONS,
                                 pid, cpu_id, pc->fd_cycles);
    if (pc->fd_instr < 0)  { perf_counter_close(pc); return -1; }

    pc->fd_llc    = open_counter(PERF_TYPE_HARDWARE,
                                 PERF_COUNT_HW_CACHE_MISSES,
                                 pid, cpu_id, pc->fd_cycles);
    if (pc->fd_llc < 0)    { perf_counter_close(pc); return -1; }

    ioctl(pc->fd_cycles, PERF_EVENT_IOC_ID, &pc->id_cycles);
    ioctl(pc->fd_instr,  PERF_EVENT_IOC_ID, &pc->id_instr);
    ioctl(pc->fd_llc,    PERF_EVENT_IOC_ID, &pc->id_llc);

    ioctl(pc->fd_cycles, PERF_EVENT_IOC_RESET,  PERF_IOC_FLAG_GROUP);
    ioctl(pc->fd_cycles, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    return 0;
}

int perf_counter_read(perf_counter_t *pc, raw_counters_t *out) {
    memset(out, 0, sizeof(*out));

    if (!pc->hw_available) {
        /* Software fallback: single non-grouped fd, read as plain uint64_t.
         * Only cycles (clock ticks) are available — instructions and LLC
         * remain 0, so IPC and LLC miss rate will be 0.0 in the classifier.
         * ctx_freq and io_freq via eBPF are unaffected. */
        uint64_t val = 0;
        if (read(pc->fd_cycles, &val, sizeof(val)) != (ssize_t)sizeof(val))
            return -1;
        out->cycles = val;
        return 0;
    }

    /* Hardware path: grouped atomic read of all three counters */
    struct read_format buf;
    ssize_t n = read(pc->fd_cycles, &buf, sizeof(buf));
    /* Reject short reads: if we can't even read the 'nr' field (8 bytes),
     * buf.nr is garbage and the loop below would iterate arbitrary times.
     * perf grouped reads are atomic in the kernel so a short read indicates
     * a real fd error, not a partial transfer. */
    if (n < (ssize_t)sizeof(uint64_t))
        return -1;

    for (uint64_t i = 0; i < buf.nr && i < 3; i++) {
        if      (buf.values[i].id == pc->id_cycles)
            out->cycles       = buf.values[i].value;
        else if (buf.values[i].id == pc->id_instr)
            out->instructions = buf.values[i].value;
        else if (buf.values[i].id == pc->id_llc)
            out->llc_misses   = buf.values[i].value;
    }
    return 0;
}

/* perf_counter_ipc() and perf_counter_llc_miss_rate() removed — dead code.
 * Both were never called from the sampling loop.  IPC and LLC miss rate
 * are computed inline in schedmon.c for correctness (window smoothing,
 * correct fraction vs percent semantics). */

void perf_counter_close(perf_counter_t *pc) {
    if (pc->fd_cycles >= 0) {
        if (pc->hw_available)
            ioctl(pc->fd_cycles, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
        else
            ioctl(pc->fd_cycles, PERF_EVENT_IOC_DISABLE, 0);
        close(pc->fd_cycles);
    }
    if (pc->fd_instr  >= 0) close(pc->fd_instr);
    if (pc->fd_llc    >= 0) close(pc->fd_llc);
    memset(pc, 0, sizeof(*pc));
    pc->fd_cycles = pc->fd_instr = pc->fd_llc = -1;
}
