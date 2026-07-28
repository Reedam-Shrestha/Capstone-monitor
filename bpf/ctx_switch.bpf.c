/* ctx_switch.bpf.c — kernel-side eBPF program */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <linux/types.h>

/* keep this name under 16 chars or the kernel truncates it silently and
 * bpftool map show gets confusing */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u64);
} vol_ctx_switch SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u32);
} active_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u64);
} io_counts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u64);
} io_wait_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u64);
} rq_enqueue_ts SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u64);
} rq_wait_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, char[16]);
} exec_comms SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   __u32);
    __type(value, __u32);
} pid_last_cpu SEC(".maps");

struct sched_switch_args {
    __u64 pad;
    char  prev_comm[16];
    __u32 prev_pid;
    __u32 prev_prio;
    __s64 prev_state;
    char  next_comm[16];
    __u32 next_pid;
    __u32 next_prio;
};

SEC("tp/sched/sched_switch")
int handle_sched_switch(struct sched_switch_args *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u32 cpu = bpf_get_smp_processor_id();

    __u32 prev_pid = ctx->prev_pid;
    __u32 next_pid = ctx->next_pid;
    if (prev_pid > 1)
        bpf_map_update_elem(&pid_last_cpu, &prev_pid, &cpu, BPF_ANY);
    if (next_pid > 1)
        bpf_map_update_elem(&pid_last_cpu, &next_pid, &cpu, BPF_ANY);

    if (prev_pid != 0 && ctx->prev_state != 0) {
        __u64 *cnt = bpf_map_lookup_elem(&vol_ctx_switch, &prev_pid);
        if (cnt) {
            __atomic_fetch_add(cnt, 1, __ATOMIC_RELAXED);
        } else {
            __u64 one = 1;
            bpf_map_update_elem(&vol_ctx_switch, &prev_pid, &one, BPF_ANY);
        }
    }

    if (next_pid == 0) return 0;

    __u64 *enqueue_ts = bpf_map_lookup_elem(&rq_enqueue_ts, &next_pid);
    if (enqueue_ts && *enqueue_ts > 0) {
        __u64 wait = now - *enqueue_ts;
        if (wait < 10000000000ULL) {
            __u64 *acc = bpf_map_lookup_elem(&rq_wait_ns, &next_pid);
            if (acc) {
                __atomic_fetch_add(acc, wait, __ATOMIC_RELAXED);
            } else {
                bpf_map_update_elem(&rq_wait_ns, &next_pid, &wait, BPF_ANY);
            }
        }
        __u64 zero = 0;
        bpf_map_update_elem(&rq_enqueue_ts, &next_pid, &zero, BPF_ANY);
    }

    return 0;
}

struct sched_wakeup_args {
    __u64 pad;
    char  comm[16];
    __u32 pid;
    __u32 prio;
    __u32 success;
    __u32 target_cpu;
};

SEC("tp/sched/sched_wakeup")
int handle_sched_wakeup(struct sched_wakeup_args *ctx) {
    __u32 pid = ctx->pid;
    if (pid <= 1) return 0;
    __u64 now = bpf_ktime_get_ns();
    bpf_map_update_elem(&rq_enqueue_ts, &pid, &now, BPF_ANY);
    return 0;
}

struct sched_process_fork_args {
    __u64 pad;
    __u32 parent_comm;
    __u32 parent_pid;
    __u32 child_comm;
    __u32 child_pid;
};

SEC("tp/sched/sched_process_fork")
int handle_fork(struct sched_process_fork_args *ctx) {
    __u32 child_pid = ctx->child_pid;
    if (child_pid <= 1) return 0;

    __u32 active = 1;
    bpf_map_update_elem(&active_pids, &child_pid, &active, BPF_ANY);

    __u64 zero = 0;
    bpf_map_update_elem(&vol_ctx_switch, &child_pid, &zero, BPF_NOEXIST);
    bpf_map_update_elem(&io_counts,        &child_pid, &zero, BPF_NOEXIST);
    bpf_map_update_elem(&io_wait_ns,       &child_pid, &zero, BPF_NOEXIST);
    bpf_map_update_elem(&rq_wait_ns,       &child_pid, &zero, BPF_NOEXIST);
    return 0;
}

struct sched_process_exit_args {
    __u64 pad;
    char  comm[16];
    __u32 pid;
    __u32 prio;
    __u8  group_dead;
};

SEC("tp/sched/sched_process_exit")
int handle_exit(struct sched_process_exit_args *ctx) {
    __u32 pid = ctx->pid;
    if (pid <= 1 || !ctx->group_dead) return 0;

    bpf_map_delete_elem(&active_pids,      &pid);
    bpf_map_delete_elem(&vol_ctx_switch, &pid);
    bpf_map_delete_elem(&io_counts,        &pid);
    bpf_map_delete_elem(&io_wait_ns,       &pid);
    bpf_map_delete_elem(&rq_enqueue_ts,    &pid);
    bpf_map_delete_elem(&rq_wait_ns,       &pid);
    bpf_map_delete_elem(&exec_comms,       &pid);
    bpf_map_delete_elem(&pid_last_cpu,     &pid);
    return 0;
}

struct sched_process_exec_args {
    __u64 pad;
    __u32 filename;
    __u32 pid;
    __u32 old_pid;
};

SEC("tp/sched/sched_process_exec")
int handle_exec(struct sched_process_exec_args *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (pid <= 1) return 0;

    char comm[16] = {};
    bpf_get_current_comm(comm, sizeof(comm));
    bpf_map_update_elem(&exec_comms, &pid, comm, BPF_ANY);

    __u32 active = 1;
    bpf_map_update_elem(&active_pids, &pid, &active, BPF_NOEXIST);
    return 0;
}

/* keying this by (dev,sector) doesnt work because the io scheduler can
 * merge requests -- issue fires at the original sector but complete fires
 * for the merged request at a different sector, so the lookup misses.
 * keying by the request pointer instead works since it stays stable
 * across merges (raw_tp gives access to ctx->args[0] which is the
 * struct request*). block_rq_issue runs in the calling process's context
 * so pid_tgid is valid there, block_rq_complete runs in softirq context
 * so we look up the pid we stored at issue time instead */

struct bio_info {
    __u64 issue_ts;   /* 8-byte aligned first — no padding before __u32 pid */
    __u32 pid;
    __u32 _pad;       /* explicit padding to natural struct size (16 bytes) */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key,   __u64);            /* key = (u64)(struct request *) — stable across merges */
    __type(value, struct bio_info);
} bio_inflight SEC(".maps");

SEC("raw_tp/block_rq_issue")
int handle_block_rq_issue(struct bpf_raw_tracepoint_args *ctx) {
    __u32 pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
    if (pid <= 1) return 0;

    __u64 rq_ptr = ctx->args[0];   /* struct request * as u64 key */

    struct bio_info info = {
        .issue_ts = bpf_ktime_get_ns(),
        .pid      = pid,
        ._pad     = 0,
    };
    bpf_map_update_elem(&bio_inflight, &rq_ptr, &info, BPF_ANY);
    return 0;
}

SEC("raw_tp/block_rq_complete")
int handle_block_rq_complete(struct bpf_raw_tracepoint_args *ctx) {
    __u64 now = bpf_ktime_get_ns();
    __u64 rq_ptr = ctx->args[0];

    struct bio_info *info = bpf_map_lookup_elem(&bio_inflight, &rq_ptr);
    if (!info) return 0;

    __u32 pid      = info->pid;
    __u64 issue_ts = info->issue_ts;

    /* delete regardless so this map doesnt just keep growing */
    bpf_map_delete_elem(&bio_inflight, &rq_ptr);

    /* skip pids we arent watching */
    __u32 *tracked = bpf_map_lookup_elem(&active_pids, &pid);
    if (!tracked) return 0;

    __u64 *cnt = bpf_map_lookup_elem(&io_counts, &pid);
    if (cnt) {
        __atomic_fetch_add(cnt, 1, __ATOMIC_RELAXED);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&io_counts, &pid, &one, BPF_ANY);
    }

    if (issue_ts > 0) {
        __u64 wait = now - issue_ts;
        if (wait < 30000000000ULL) {
            __u64 *acc = bpf_map_lookup_elem(&io_wait_ns, &pid);
            if (acc) {
                __atomic_fetch_add(acc, wait, __ATOMIC_RELAXED);
            } else {
                bpf_map_update_elem(&io_wait_ns, &pid, &wait, BPF_ANY);
            }
        }
    }

    return 0;
}

char _license[] SEC("license") = "GPL";