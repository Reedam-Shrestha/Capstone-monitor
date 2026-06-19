#include "ebpf_tracer.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

/* ── helpers ────────────────────────────────────────────────────────────── */

static int find_map_fd(struct bpf_object *obj, const char *name) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (!map) {
        fprintf(stderr, "[ebpf_tracer] Cannot find map '%s'\n", name);
        return -1;
    }
    int fd = bpf_map__fd(map);
    if (fd < 0)
        fprintf(stderr, "[ebpf_tracer] bpf_map__fd('%s') failed\n", name);
    return fd;
}

static struct bpf_link *attach_prog(struct bpf_object *obj,
                                    const char *prog_name) {
    struct bpf_program *prog =
        bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        fprintf(stderr, "[ebpf_tracer] Cannot find program '%s'\n", prog_name);
        return NULL;
    }
    struct bpf_link *link = bpf_program__attach(prog);
    if (!link)
        fprintf(stderr, "[ebpf_tracer] attach '%s' failed: %s\n",
                prog_name, strerror(errno));
    return link;
}

/* ── ebpf_tracer_load ───────────────────────────────────────────────────── */

int ebpf_tracer_load(ebpf_tracer_t *et, const char *bpf_path) {
    memset(et, 0, sizeof(*et));
    et->map_fd_switches  = -1;
    et->map_fd_pids      = -1;
    et->map_fd_io        = -1;
    et->map_fd_io_wait   = -1;
    et->map_fd_rq_wait   = -1;
    et->map_fd_last_cpu  = -1;
    et->map_fd_exec      = -1;

    et->obj = bpf_object__open(bpf_path);
    if (!et->obj) {
        fprintf(stderr, "[ebpf_tracer] bpf_object__open(%s) failed: %s\n",
                bpf_path, strerror(errno));
        return -1;
    }

    int err = bpf_object__load(et->obj);
    if (err) {
        fprintf(stderr, "[ebpf_tracer] bpf_object__load failed: %s\n",
                strerror(-err));
        fprintf(stderr, "  Hint: /sys/kernel/btf/vmlinux must exist\n");
        fprintf(stderr, "  Hint: run as root\n");
        bpf_object__close(et->obj);
        et->obj = NULL;
        return -1;
    }

    /* Required maps — failure is fatal */
    et->map_fd_switches = find_map_fd(et->obj, "vol_ctx_switches");
    et->map_fd_pids     = find_map_fd(et->obj, "active_pids");
    if (et->map_fd_switches < 0 || et->map_fd_pids < 0) {
        bpf_object__close(et->obj);
        et->obj = NULL;
        return -1;
    }

    /* Optional maps — non-fatal if missing */
    et->map_fd_io = find_map_fd(et->obj, "io_counts");
    if (et->map_fd_io < 0)
        fprintf(stderr, "[ebpf_tracer] io_counts map unavailable"
                        " — io_freq will be 0\n");

    et->map_fd_io_wait = find_map_fd(et->obj, "io_wait_ns");
    if (et->map_fd_io_wait < 0)
        fprintf(stderr, "[ebpf_tracer] io_wait_ns map unavailable"
                        " — io_wait_ms will be 0\n");

    et->map_fd_rq_wait = find_map_fd(et->obj, "rq_wait_ns");
    if (et->map_fd_rq_wait < 0)
        fprintf(stderr, "[ebpf_tracer] rq_wait_ns map unavailable"
                        " — rq_wait_ms will be 0\n");

    et->map_fd_last_cpu = find_map_fd(et->obj, "pid_last_cpu");
    if (et->map_fd_last_cpu < 0)
        fprintf(stderr, "[ebpf_tracer] pid_last_cpu map unavailable"
                        " — last_cpu tracking disabled\n");

    et->map_fd_exec = find_map_fd(et->obj, "exec_comms");
    if (et->map_fd_exec < 0)
        fprintf(stderr, "[ebpf_tracer] exec_comms map unavailable"
                        " — comm read from /proc\n");

    et->loaded = 1;
    printf("[ebpf_tracer] Loaded %s  switches_fd=%d  pids_fd=%d"
           "  io_fd=%d  io_wait_fd=%d  rq_wait_fd=%d\n",
           bpf_path, et->map_fd_switches, et->map_fd_pids,
           et->map_fd_io, et->map_fd_io_wait, et->map_fd_rq_wait);
    return 0;
}

/* ── ebpf_tracer_attach ─────────────────────────────────────────────────── */

int ebpf_tracer_attach(ebpf_tracer_t *et) {
    if (!et->loaded) {
        fprintf(stderr, "[ebpf_tracer] Not loaded.\n");
        return -1;
    }

    et->link_sched_switch = attach_prog(et->obj, "handle_sched_switch");
    et->link_fork         = attach_prog(et->obj, "handle_fork");
    et->link_exit         = attach_prog(et->obj, "handle_exit");

    if (!et->link_sched_switch || !et->link_fork || !et->link_exit) {
        fprintf(stderr, "[ebpf_tracer] Fatal tracepoint attach failed.\n");
        return -1;
    }

    /* sched_wakeup — non-fatal; provides runqueue wait time */
    et->link_sched_wakeup = attach_prog(et->obj, "handle_sched_wakeup");
    if (!et->link_sched_wakeup)
        fprintf(stderr, "[ebpf_tracer] sched_wakeup attach failed"
                        " — rq_wait_ms will be 0 (non-fatal)\n");

    /* block_rq_issue — non-fatal; needed for io_wait_ms */
    et->link_block_issue = attach_prog(et->obj, "handle_block_rq_issue");
    if (!et->link_block_issue)
        fprintf(stderr, "[ebpf_tracer] block_rq_issue attach failed"
                        " — io_wait_ms will be 0 (non-fatal)\n");

    /* block_rq_complete — non-fatal; needed for io_freq + io_wait_ms */
    et->link_block = attach_prog(et->obj, "handle_block_rq_complete");
    if (!et->link_block)
        fprintf(stderr, "[ebpf_tracer] block_rq_complete attach failed"
                        " — io_freq/io_wait_ms will be 0 (non-fatal)\n");

    /* exec tracepoint — non-fatal */
    et->link_exec = attach_prog(et->obj, "handle_exec");
    if (!et->link_exec)
        fprintf(stderr, "[ebpf_tracer] sched_process_exec attach failed"
                        " — comm read from /proc (non-fatal)\n");

    printf("[ebpf_tracer] Attached: sched_switch + fork + exit%s%s%s%s\n",
           et->link_sched_wakeup ? " + sched_wakeup"      : "",
           et->link_block_issue  ? " + block_rq_issue"    : "",
           et->link_block        ? " + block_rq_complete" : "",
           et->link_exec         ? " + exec"              : "");
    return 0;
}

/* ── readers ────────────────────────────────────────────────────────────── */
uint64_t ebpf_tracer_read_switches(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_switches < 0) return 0;
    uint64_t v = 0;
    int ret = bpf_map_lookup_elem(et->map_fd_switches, &pid, &v);
    if (ret < 0) return 0;
    return v;
}

uint64_t ebpf_tracer_read_io(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_io < 0) return 0;
    uint64_t v = 0;
    int ret = bpf_map_lookup_elem(et->map_fd_io, &pid, &v);
    if (ret < 0) return 0;
    return v;
}

uint64_t ebpf_tracer_read_io_wait_ns(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_io_wait < 0) return 0;
    uint64_t v = 0;
    int ret = bpf_map_lookup_elem(et->map_fd_io_wait, &pid, &v);
    if (ret < 0) return 0;
    return v;
}

uint64_t ebpf_tracer_read_rq_wait_ns(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_rq_wait < 0) return 0;
    uint64_t v = 0;
    int ret = bpf_map_lookup_elem(et->map_fd_rq_wait, &pid, &v);
    if (ret < 0) return 0;
    return v;
}
/*
 * ebpf_tracer_read_last_cpu — returns the last CPU id where pid ran,
 * or -1 if the map is unavailable or the pid has no entry yet.
 * This is read by the slow path to fill SmoothedMetrics.cpu_id for the
 * aggregate entry, giving ghOSt confirmed evidence of where the process ran.
 */
int ebpf_tracer_read_last_cpu(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_last_cpu < 0) return -1;
    uint32_t cpu = 0;
    if (bpf_map_lookup_elem(et->map_fd_last_cpu, &pid, &cpu) != 0)
        return -1;
    return (int)cpu;
}

/* ── ebpf_tracer_get_active_pids ────────────────────────────────────────── */

int ebpf_tracer_get_active_pids(const ebpf_tracer_t *et,
                                uint32_t *pids, int max_pids) {
    if (et->map_fd_pids < 0) return 0;

    enum { MAP_MAX = 10240 };
    static uint32_t batch_keys  [MAP_MAX];
    static uint32_t batch_values[MAP_MAX];
    uint32_t batch_count = (max_pids < MAP_MAX) ? (uint32_t)max_pids : MAP_MAX;

    int err = bpf_map_lookup_batch(et->map_fd_pids, NULL, NULL,
                                   batch_keys, batch_values,
                                   &batch_count, NULL);

    if (err == 0 || (err < 0 && errno == ENOENT)) {
        for (uint32_t i = 0; i < batch_count; i++)
            pids[i] = batch_keys[i];
        return (int)batch_count;
    }
    return 0;
}

/* ── ebpf_tracer_pop_exec_comm ──────────────────────────────────────────── */

int ebpf_tracer_pop_exec_comm(const ebpf_tracer_t *et,
                              uint32_t pid, char *buf, int len) {
    if (et->map_fd_exec < 0 || !buf || len <= 0)
        return 0;

    char comm[16] = {};
    if (bpf_map_lookup_elem(et->map_fd_exec, &pid, comm) != 0)
        return 0;

    int copy_len = len - 1 < 16 ? len - 1 : 16;
    int i;
    for (i = 0; i < copy_len && comm[i] != '\0'; i++)
        buf[i] = comm[i];
    buf[i] = '\0';

    bpf_map_delete_elem(et->map_fd_exec, &pid);
    return 1;
}

/* ── ebpf_tracer_register_pid ───────────────────────────────────────────────
 * Insert pid into the BPF active_pids map from userspace.
 * Called by add_pid() so pre-existing processes and explicitly listed PIDs
 * are visible to the block_rq_issue/complete tracepoints.
 * Also initialises io_counts, io_wait_ns and rq_wait_ns to 0 if not present,
 * mirroring what handle_fork does for newly created processes.
 */
void ebpf_tracer_register_pid(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_pids < 0) return;

    uint32_t active = 1;
    bpf_map_update_elem(et->map_fd_pids, &pid, &active, BPF_ANY);

    /* Initialise counters to 0 if not already present (BPF_NOEXIST so we
     * don't reset counters for a process that was already being tracked by
     * the fork/exec tracepoints before userspace caught up). */
    uint64_t zero = 0;
    if (et->map_fd_io      >= 0) bpf_map_update_elem(et->map_fd_io,      &pid, &zero, BPF_NOEXIST);
    if (et->map_fd_io_wait >= 0) bpf_map_update_elem(et->map_fd_io_wait, &pid, &zero, BPF_NOEXIST);
    if (et->map_fd_rq_wait >= 0) bpf_map_update_elem(et->map_fd_rq_wait, &pid, &zero, BPF_NOEXIST);
}

/* ── ebpf_tracer_unregister_pid ─────────────────────────────────────────────
 * Remove pid from the BPF active_pids map when the monitor stops tracking it.
 * Does NOT delete the counter maps — the final delta was already consumed by
 * remove_slot before this is called.
 */
void ebpf_tracer_unregister_pid(const ebpf_tracer_t *et, uint32_t pid) {
    if (et->map_fd_pids < 0) return;
    bpf_map_delete_elem(et->map_fd_pids, &pid);
}

/* ── ebpf_tracer_destroy ────────────────────────────────────────────────── */

void ebpf_tracer_destroy(ebpf_tracer_t *et) {
    if (et->link_sched_switch) { bpf_link__destroy(et->link_sched_switch); et->link_sched_switch = NULL; }
    if (et->link_sched_wakeup) { bpf_link__destroy(et->link_sched_wakeup); et->link_sched_wakeup = NULL; }
    if (et->link_fork)         { bpf_link__destroy(et->link_fork);         et->link_fork         = NULL; }
    if (et->link_exit)         { bpf_link__destroy(et->link_exit);         et->link_exit         = NULL; }
    if (et->link_block_issue)  { bpf_link__destroy(et->link_block_issue);  et->link_block_issue  = NULL; }
    if (et->link_block)        { bpf_link__destroy(et->link_block);        et->link_block        = NULL; }
    if (et->link_exec)         { bpf_link__destroy(et->link_exec);         et->link_exec         = NULL; }
    if (et->obj)               { bpf_object__close(et->obj);               et->obj               = NULL; }
    et->map_fd_switches = et->map_fd_pids    = -1;
    et->map_fd_io       = et->map_fd_io_wait = -1;
    et->map_fd_rq_wait  = et->map_fd_last_cpu = -1;
    et->map_fd_exec     = -1;
    et->loaded = 0;
    printf("[ebpf_tracer] Destroyed.\n");
}
