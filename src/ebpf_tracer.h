#ifndef EBPF_TRACER_H
#define EBPF_TRACER_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

typedef struct {
    struct bpf_object *obj;
    struct bpf_link   *link_sched_switch;
    struct bpf_link   *link_sched_wakeup;
    struct bpf_link   *link_fork;
    struct bpf_link   *link_exit;
    struct bpf_link   *link_block_issue;
    struct bpf_link   *link_block;
    struct bpf_link   *link_exec;
    int                map_fd_switches;
    int                map_fd_pids;
    int                map_fd_io;
    int                map_fd_io_wait;
    int                map_fd_rq_wait;
    int                map_fd_last_cpu;
    int                map_fd_exec;
    int                loaded;
} ebpf_tracer_t;

int      ebpf_tracer_load   (ebpf_tracer_t *et, const char *bpf_path);
int      ebpf_tracer_attach (ebpf_tracer_t *et);
void     ebpf_tracer_destroy(ebpf_tracer_t *et);

uint64_t ebpf_tracer_read_switches  (const ebpf_tracer_t *et, uint32_t pid);
uint64_t ebpf_tracer_read_io        (const ebpf_tracer_t *et, uint32_t pid);
uint64_t ebpf_tracer_read_io_wait_ns(const ebpf_tracer_t *et, uint32_t pid);
uint64_t ebpf_tracer_read_rq_wait_ns(const ebpf_tracer_t *et, uint32_t pid);
int      ebpf_tracer_read_last_cpu  (const ebpf_tracer_t *et, uint32_t pid);

int ebpf_tracer_get_active_pids(const ebpf_tracer_t *et,
                                uint32_t *pids, int max_pids);
int ebpf_tracer_pop_exec_comm  (const ebpf_tracer_t *et,
                                uint32_t pid, char *buf, int len);

/* call register_pid when we start watching a pid, unregister when we stop.
 * active_pids map only gets filled by fork/exec hooks normally, so pids
 * that already existed before the daemon started (or passed via --pids)
 * need to be added by hand or block io tracking wont see them */
void ebpf_tracer_register_pid  (const ebpf_tracer_t *et, uint32_t pid);
void ebpf_tracer_unregister_pid(const ebpf_tracer_t *et, uint32_t pid);

#endif /* EBPF_TRACER_H */