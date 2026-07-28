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
#include <stdbool.h>

struct read_format {
    uint64_t nr;
    struct { uint64_t value; uint64_t id; } values[3];
};

static long perf_event_open(struct perf_event_attr *hw_event,
                             pid_t pid, int cpu, int group_fd,
                             unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/* prints a different message when we ran out of fds vs an actual pmu
 * problem, since those need totally different fixes */
static void report_open_failure(const char *what, pid_t pid, int cpu_id, int err) {
    if (err == EMFILE || err == ENFILE) {
        fprintf(stderr,
            "perf_counter: FILE DESCRIPTOR LIMIT REACHED opening %s for pid=%d"
            " (cpu=%d): %s\n"
            "  not a pmu problem, raise ulimit -n or LimitNOFILE in the service file\n",
            what, (int)pid, cpu_id, strerror(err));
    } else {
        fprintf(stderr, "perf_counter: %s failed for pid=%d (cpu=%d): %s\n",
                what, (int)pid, cpu_id, strerror(err));
    }
}

static int open_counter(uint32_t type, uint64_t config,
                        pid_t pid, int cpu_id, int leader_fd,
                        bool is_group_leader, int *out_errno) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type       = type;
    pe.size       = sizeof(pe);
    pe.config     = config;
    pe.disabled   = 1;
    pe.exclude_hv = 1;
    /* only set group format on the actual group leader. setting it on the
     * lone software fallback counter makes the kernel return group-shaped
     * reads instead of a plain u64 and breaks perf_counter_read for it */
    if (is_group_leader)
        pe.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_ID;
    int fd = perf_event_open(&pe, pid, cpu_id, leader_fd, 0);
    if (fd == -1) {
        if (out_errno) *out_errno = errno;
    } else if (out_errno) {
        *out_errno = 0;
    }
    return fd;
}

int perf_counter_open(perf_counter_t *pc, pid_t pid, int cpu_id) {
    memset(pc, 0, sizeof(*pc));
    pc->pid    = pid;
    pc->cpu_id = cpu_id;
    pc->fd_cycles = pc->fd_instr = pc->fd_llc = -1;
    pc->hw_available = 1;

    int open_errno = 0;
    pc->fd_cycles = open_counter(PERF_TYPE_HARDWARE,
                                 PERF_COUNT_HW_CPU_CYCLES, pid, cpu_id, -1,
                                 true, &open_errno);
    if (pc->fd_cycles < 0) {
        if (open_errno == EMFILE || open_errno == ENFILE) {
            report_open_failure("hardware cycles counter", pid, cpu_id, open_errno);
            pc->hw_available = 0;
            return -1;
        }

        fprintf(stderr, "perf_counter: hardware PMU unavailable for pid=%d"
                        " — falling back to software clock counter\n", (int)pid);
        pc->hw_available = 0;

        pc->fd_cycles = open_counter(PERF_TYPE_SOFTWARE,
                                     PERF_COUNT_SW_CPU_CLOCK, pid, cpu_id, -1,
                                     false, &open_errno);
        if (pc->fd_cycles < 0) {
            report_open_failure("software fallback counter", pid, cpu_id, open_errno);
            return -1;
        }
        ioctl(pc->fd_cycles, PERF_EVENT_IOC_RESET,  0);
        ioctl(pc->fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
        return 0;
    }

    pc->fd_instr  = open_counter(PERF_TYPE_HARDWARE,
                                 PERF_COUNT_HW_INSTRUCTIONS,
                                 pid, cpu_id, pc->fd_cycles,
                                 false, &open_errno);
    if (pc->fd_instr < 0) {
        report_open_failure("instructions counter", pid, cpu_id, open_errno);
        perf_counter_close(pc);
        return -1;
    }

    pc->fd_llc    = open_counter(PERF_TYPE_HARDWARE,
                                 PERF_COUNT_HW_CACHE_MISSES,
                                 pid, cpu_id, pc->fd_cycles,
                                 false, &open_errno);
    if (pc->fd_llc < 0) {
        report_open_failure("LLC-misses counter", pid, cpu_id, open_errno);
        perf_counter_close(pc);
        return -1;
    }

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
        /* just cycles here, instr/llc stay 0 which makes ipc/llc_miss 0 too */
        uint64_t val = 0;
        if (read(pc->fd_cycles, &val, sizeof(val)) != (ssize_t)sizeof(val))
            return -1;
        out->cycles = val;
        return 0;
    }

    struct read_format buf;
    ssize_t n = read(pc->fd_cycles, &buf, sizeof(buf));
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