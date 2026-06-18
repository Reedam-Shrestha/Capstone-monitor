#include "ring_buffer.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

/* ── internal helpers — parameterised on shm name ───────────────────────── */

static RingBuffer *mmap_shm(int fd) {
    return (RingBuffer *)mmap(NULL, sizeof(RingBuffer),
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED, fd, 0);
}

static RingBuffer *rb_create_named(const char *name) {
    shm_unlink(name);   /* remove stale shm from previous run */

    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { perror("shm_open create"); return NULL; }

    /* FIX: fchmod AFTER the fd validity check.
     * shm_open honours the process umask, so a restrictive umask (e.g. 0077
     * common for root services) would create the shm as 0600 despite the
     * 0666 mode argument.  fchmod forces world-read/write so that unprivileged
     * consumers (classifier, dashboard) can attach. */
    if (fchmod(fd, 0666) < 0)
        perror("shm fchmod create");   /* non-fatal: log and continue */

    if (ftruncate(fd, sizeof(RingBuffer)) < 0) {
        perror("ftruncate"); close(fd); return NULL;
    }

    RingBuffer *rb = mmap_shm(fd);
    close(fd);
    if (rb == MAP_FAILED) { perror("mmap create"); return NULL; }

    memset(rb->slots, 0, sizeof(rb->slots));
    atomic_store(&rb->head, 0);
    atomic_store(&rb->tail, 0);
    /* capacity field removed — all paths use RB_CAPACITY compile-time constant */
    return rb;
}

static RingBuffer *rb_attach_named(const char *name) {
    int fd = shm_open(name, O_RDWR, 0666);
    if (fd < 0) { perror("shm_open attach"); return NULL; }
    /* Note: do NOT call fchmod here — non-root consumers will get EPERM
     * trying to chmod shm owned by root.  The creator already set 0666. */

    RingBuffer *rb = mmap_shm(fd);
    close(fd);
    if (rb == MAP_FAILED) { perror("mmap attach"); return NULL; }
    return rb;
}

static void rb_destroy_named(RingBuffer *rb, const char *name) {
    munmap(rb, sizeof(RingBuffer));
    shm_unlink(name);
}

/* ── public API — classifier buffer (/monitor_rb) ───────────────────────── */

RingBuffer *rb_create(void) {
    return rb_create_named(SHM_NAME);
}

RingBuffer *rb_attach(void) {
    return rb_attach_named(SHM_NAME);
}

void rb_destroy(RingBuffer *rb) {
    rb_destroy_named(rb, SHM_NAME);
}

/* ── public API — dashboard buffer (/monitor_rb_dash) ───────────────────── */

RingBuffer *rb_create_dash(void) {
    return rb_create_named(SHM_NAME_DASH);
}

RingBuffer *rb_attach_dash(void) {
    return rb_attach_named(SHM_NAME_DASH);
}

void rb_destroy_dash(RingBuffer *rb) {
    rb_destroy_named(rb, SHM_NAME_DASH);
}

/* ── public API — scheduler buffer (/monitor_rb_sched) ──────────────────── */

RingBuffer *rb_create_sched(void) {
    return rb_create_named(SHM_NAME_SCHED);
}

RingBuffer *rb_attach_sched(void) {
    return rb_attach_named(SHM_NAME_SCHED);
}

void rb_destroy_sched(RingBuffer *rb) {
    rb_destroy_named(rb, SHM_NAME_SCHED);
}

/* ── shared: detach without unlinking ───────────────────────────────────── */

void rb_detach(RingBuffer *rb) {
    munmap(rb, sizeof(RingBuffer));
}

/* ── shared: push (producer) ─────────────────────────────────────────────── */

bool rb_push(RingBuffer *rb, const SmoothedMetrics *m) {
    int head      = atomic_load_explicit(&rb->head, memory_order_relaxed);
    int next_head = (head + 1) % RB_CAPACITY;

    /* Full: drop and return false — do NOT advance the tail here.
     * Advancing the tail from the producer side races with the consumer
     * reading rb->slots[tail] and can corrupt the slot being read. */
    if (next_head == atomic_load_explicit(&rb->tail, memory_order_acquire))
        return false;

    rb->slots[head] = *m;

    /* RELEASE: slot write must be visible before head advances */
    atomic_store_explicit(&rb->head, next_head, memory_order_release);
    return true;
}

/* ── shared: pop (consumer) ──────────────────────────────────────────────── */

bool rb_pop(RingBuffer *rb, SmoothedMetrics *out) {
    int tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

    /* empty */
    if (tail == atomic_load_explicit(&rb->head, memory_order_acquire))
        return false;

    *out = rb->slots[tail];

    /* RELEASE: slot read must finish before tail advances */
    atomic_store_explicit(&rb->tail,
                          (tail + 1) % RB_CAPACITY,
                          memory_order_release);
    return true;
}

/* ── shared: status checks ───────────────────────────────────────────────── */

bool rb_is_full(const RingBuffer *rb) {
    int next = (atomic_load(&rb->head) + 1) % RB_CAPACITY;
    return next == atomic_load(&rb->tail);
}

bool rb_is_empty(const RingBuffer *rb) {
    return atomic_load(&rb->head) == atomic_load(&rb->tail);
}
