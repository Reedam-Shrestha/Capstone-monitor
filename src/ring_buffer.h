#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <stdatomic.h>
#include <stdbool.h>
#include "smoothed_metrics.h"

/* power of 2, must be >= MAX_PIDS. 32768 is way more headroom than we
 * actually need since its just one aggregate entry per pid per tick now */
#define RB_CAPACITY    32768

#define RB_MAX_PIDS    256

_Static_assert(RB_CAPACITY >= RB_MAX_PIDS, "capacity too small");
_Static_assert((RB_CAPACITY & (RB_CAPACITY - 1)) == 0, "must be power of 2");

#define SHM_NAME       "/monitor_rb"
#define SHM_NAME_DASH  "/monitor_rb_dash"

typedef struct {
    SmoothedMetrics slots[RB_CAPACITY];
    atomic_int      head;
    atomic_int      tail;
    uint32_t        abi_version;
    uint32_t        slot_size;
} RingBuffer;

RingBuffer *rb_create      (void);
RingBuffer *rb_create_dash (void);
bool        rb_push        (RingBuffer *rb, const SmoothedMetrics *m);

RingBuffer *rb_attach      (void);
RingBuffer *rb_attach_dash (void);
bool        rb_pop         (RingBuffer *rb, SmoothedMetrics *out);

void rb_destroy      (RingBuffer *rb);
void rb_destroy_dash (RingBuffer *rb);
void rb_detach       (RingBuffer *rb);

bool rb_is_full (const RingBuffer *rb);
bool rb_is_empty(const RingBuffer *rb);

/* call after attach, checks abi_version + slot_size match. false = mismatch,
 * caller decides what to do about it */
bool rb_check_abi(const RingBuffer *rb);

#endif /* RING_BUFFER_H */