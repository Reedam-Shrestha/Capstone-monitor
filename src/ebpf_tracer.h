#ifndef EBPF_TRACER_H
#define EBPF_TRACER_H

#include <stdint.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

typedef struct {
    struct bpf_object *obj;
    struct bpf_link   *link_sched_switch;
    struct bpf_link   *link_sched_wakeup;   /* rq wait time (non-fatal)  */
    struct bpf_link   *link_fork;
    struct bpf_link   *link_exit;
    struct bpf_link   *link_block_issue;    /* block_rq_issue (non-fatal) */
    struct bpf_link   *link_block;          /* block_rq_complete          */
    struct bpf_link   *link_exec;
    int                map_fd_switches;
    int                map_fd_pids;
    int                map_fd_io;
    int                map_fd_io_wait;      /* pid → cumulative io wait ns */
    int                map_fd_rq_wait;      /* pid → cumulative rq  wait ns */
    int                map_fd_last_cpu;     /* pid → last cpu id            */
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

/*
 * ebpf_tracer_register_pid / ebpf_tracer_unregister_pid
 *
 * Userspace must call register_pid whenever it starts monitoring a PID
 * (in add_pid) and unregister_pid when it stops (in remove_slot).
 *
 * The BPF active_pids map is normally populated only by handle_fork and
 * handle_exec — tracepoints that fire only for processes created after the
 * BPF program attached.  Pre-existing processes (started before the daemon,
 * or added via --pids) never hit those tracepoints, so they are invisible
 * to the block_rq_issue guard on active_pids.  These functions bridge that
 * gap from userspace so I/O is tracked for all monitored PIDs.
 */
void ebpf_tracer_register_pid  (const ebpf_tracer_t *et, uint32_t pid);
void ebpf_tracer_unregister_pid(const ebpf_tracer_t *et, uint32_t pid);

#endif /* EBPF_TRACER_H */
