#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdatomic.h>
#include <stdbool.h>
#include "smoothed_metrics.h"

/*
 * RB_CAPACITY — must be a power of 2.
 *
 * Worst-case burst with per-core on (default):
 *   MAX_PIDS=256, MAX_CORES=64
 *   entries/tick = 256 * (1 + 64) = 16 640
 *   32768 gives ~2x headroom.
 *
 * The static_asserts below catch any future accidental reduction.
 */
#define RB_CAPACITY    32768

/* Mirror MAX_PIDS / MAX_CORES without pulling in schedmon.h */
#define RB_MAX_PIDS    256
#define RB_MAX_CORES    64

_Static_assert(RB_CAPACITY >= RB_MAX_PIDS * (1 + RB_MAX_CORES),
    "RB_CAPACITY too small for per-core mode: must be >= MAX_PIDS*(1+MAX_CORES)");
_Static_assert((RB_CAPACITY & (RB_CAPACITY - 1)) == 0,
    "RB_CAPACITY must be a power of 2");

/*
 * Shared-memory object names.
 *
 * SHM_NAME       — classifier reads here: AGGREGATE ONLY (cpu_id == -1).
 *                  One entry per PID per 200ms slow-path tick (the only
 *                  cadence at which smoothed metric values actually change).
 *                  The fast path does NOT write here — it only writes to
 *                  SHM_NAME_SCHED.  Bigyan's classifier should only see
 *                  this buffer.
 *
 * SHM_NAME_DASH  — dashboard reads here: aggregate + per-core, slow-path
 *                  cadence (200ms).  Separate tail so the dashboard draining
 *                  at human-visible rates never starves the classifier.
 *
 * SHM_NAME_SCHED — scheduler / ghOSt agent reads here: PER-CORE ONLY
 *                  (cpu_id >= 0).  One entry per (PID, core) pair that had
 *                  non-zero cycles in the last 200ms slow-path interval.
 *                  The scheduler uses this to decide which processes to
 *                  migrate: high rq_wait_ms on a core signals overload,
 *                  high IPC on a specific core helps with cache-affinity
 *                  decisions.  Aggregate entries are never written here.
 */
#define SHM_NAME       "/monitor_rb"
#define SHM_NAME_DASH  "/monitor_rb_dash"
#define SHM_NAME_SCHED "/monitor_rb_sched"

typedef struct {
    SmoothedMetrics slots[RB_CAPACITY];
    atomic_int      head;   /* producer writes here  */
    atomic_int      tail;   /* consumer reads here   */
    /*
     * capacity field intentionally omitted — all code uses RB_CAPACITY
     * directly.  A runtime field that could diverge from the compile-time
     * constant was the root cause of the rb_pop/rb_is_full modulo-asymmetry
     * bug observed after stale shm reattach.
     */
    uint32_t        abi_version; /* MONITOR_ABI_VERSION of the producer that
                                   * created this segment. Written ONCE in
                                   * rb_create*(), never touched again — does
                                   * not participate in index/wrap math, so it
                                   * cannot reintroduce the bug noted above. */
    uint32_t        slot_size;   /* sizeof(SmoothedMetrics) of the producer.
                                   * Catches a struct-layout skew even if a
                                   * consumer forgot to bump ABI_VERSION. */
} RingBuffer;

/* ── Producer (schedmon daemon) ─────────────────────────────────────── */
RingBuffer *rb_create      (void);   /* creates /monitor_rb       — classifier  */
RingBuffer *rb_create_dash (void);   /* creates /monitor_rb_dash  — dashboard   */
RingBuffer *rb_create_sched(void);   /* creates /monitor_rb_sched — scheduler   */
bool        rb_push        (RingBuffer *rb, const SmoothedMetrics *m);

/* ── Consumer (classifier, dashboard, ghOSt agent) ───────────────────────── */
RingBuffer *rb_attach      (void);   /* attaches /monitor_rb       */
RingBuffer *rb_attach_dash (void);   /* attaches /monitor_rb_dash  */
RingBuffer *rb_attach_sched(void);   /* attaches /monitor_rb_sched */
bool        rb_pop         (RingBuffer *rb, SmoothedMetrics *out);

/* ── Cleanup ─────────────────────────────────────────────────────────────── */
void rb_destroy      (RingBuffer *rb);   /* unmap + unlink /monitor_rb       */
void rb_destroy_dash (RingBuffer *rb);   /* unmap + unlink /monitor_rb_dash  */
void rb_destroy_sched(RingBuffer *rb);   /* unmap + unlink /monitor_rb_sched */
void rb_detach       (RingBuffer *rb);   /* unmap only, no unlink            */

bool rb_is_full (const RingBuffer *rb);
bool rb_is_empty(const RingBuffer *rb);

/*
 * rb_check_abi — call once right after rb_attach*() / rb_attach_dash() /
 * rb_attach_sched().  Returns true if this segment was created by a
 * producer compiled against the same smoothed_metrics.h (same
 * MONITOR_ABI_VERSION AND same sizeof(SmoothedMetrics)).  On mismatch,
 * prints a diagnostic to stderr and returns false; the caller decides
 * whether to refuse to run, retry, or degrade.
 */
bool rb_check_abi(const RingBuffer *rb);

#endif /* RING_BUFFER_H */
