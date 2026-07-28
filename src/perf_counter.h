#ifndef PERF_COUNTER_H
#define PERF_COUNTER_H

#include <stdint.h>
#include <sys/types.h>

typedef struct {
    uint64_t cycles;
    uint64_t instructions;
    uint64_t llc_misses;
} raw_counters_t;

typedef struct {
    pid_t    pid;
    int      cpu_id;        /* -1 = aggregate, >=0 = pinned core (unused now) */
    int      fd_cycles;
    int      fd_instr;
    int      fd_llc;
    int      hw_available;  /* 0 means we fell back to software clock */
    uint64_t id_cycles;
    uint64_t id_instr;
    uint64_t id_llc;
} perf_counter_t;

/* cpu_id -1 follows the process across cores, >=0 pins to a core (not
 * really used anymore since we dropped per core tracking) */
int    perf_counter_open (perf_counter_t *pc, pid_t pid, int cpu_id);
int    perf_counter_read (perf_counter_t *pc, raw_counters_t *out);
void   perf_counter_close(perf_counter_t *pc);

#endif /* PERF_COUNTER_H */