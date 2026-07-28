#include "ring_buffer.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

static RingBuffer *mmap_shm(int fd) {
    return (RingBuffer *)mmap(NULL, sizeof(RingBuffer),
                              PROT_READ | PROT_WRITE,
                              MAP_SHARED, fd, 0);
}

static RingBuffer *rb_create_named(const char *name) {
    shm_unlink(name);

    int fd = shm_open(name, O_CREAT | O_RDWR, 0666);
    if (fd < 0) { perror("shm_open create"); return NULL; }

    /* umask can strip the perms we asked for so chmod again just in case,
     * otherwise non-root consumers cant attach */
    if (fchmod(fd, 0666) < 0)
        perror("shm fchmod create");

    if (ftruncate(fd, sizeof(RingBuffer)) < 0) {
        perror("ftruncate"); close(fd); return NULL;
    }

    RingBuffer *rb = mmap_shm(fd);
    close(fd);
    if (rb == MAP_FAILED) { perror("mmap create"); return NULL; }

    memset(rb->slots, 0, sizeof(rb->slots));
    atomic_store(&rb->head, 0);
    atomic_store(&rb->tail, 0);
    rb->abi_version = MONITOR_ABI_VERSION;
    rb->slot_size   = (uint32_t)sizeof(SmoothedMetrics);
    return rb;
}

static RingBuffer *rb_attach_named(const char *name) {
    int fd = shm_open(name, O_RDWR, 0666);
    if (fd < 0) { perror("shm_open attach"); return NULL; }

    RingBuffer *rb = mmap_shm(fd);
    close(fd);
    if (rb == MAP_FAILED) { perror("mmap attach"); return NULL; }
    return rb;
}

static void rb_destroy_named(RingBuffer *rb, const char *name) {
    munmap(rb, sizeof(RingBuffer));
    shm_unlink(name);
}

RingBuffer *rb_create(void) {
    return rb_create_named(SHM_NAME);
}

RingBuffer *rb_attach(void) {
    return rb_attach_named(SHM_NAME);
}

void rb_destroy(RingBuffer *rb) {
    rb_destroy_named(rb, SHM_NAME);
}

RingBuffer *rb_create_dash(void) {
    return rb_create_named(SHM_NAME_DASH);
}

RingBuffer *rb_attach_dash(void) {
    return rb_attach_named(SHM_NAME_DASH);
}

void rb_destroy_dash(RingBuffer *rb) {
    rb_destroy_named(rb, SHM_NAME_DASH);
}

void rb_detach(RingBuffer *rb) {
    munmap(rb, sizeof(RingBuffer));
}

bool rb_push(RingBuffer *rb, const SmoothedMetrics *m) {
    int head      = atomic_load_explicit(&rb->head, memory_order_relaxed);
    int next_head = (head + 1) % RB_CAPACITY;

    /* dont advance tail here even when full, producer touching tail
     * races with the consumer reading that slot */
    if (next_head == atomic_load_explicit(&rb->tail, memory_order_acquire))
        return false;

    rb->slots[head] = *m;
    atomic_store_explicit(&rb->head, next_head, memory_order_release);
    return true;
}

bool rb_pop(RingBuffer *rb, SmoothedMetrics *out) {
    int tail = atomic_load_explicit(&rb->tail, memory_order_relaxed);

    if (tail == atomic_load_explicit(&rb->head, memory_order_acquire))
        return false;

    *out = rb->slots[tail];
    atomic_store_explicit(&rb->tail,
                          (tail + 1) % RB_CAPACITY,
                          memory_order_release);
    return true;
}

bool rb_is_full(const RingBuffer *rb) {
    int next = (atomic_load(&rb->head) + 1) % RB_CAPACITY;
    return next == atomic_load(&rb->tail);
}

bool rb_is_empty(const RingBuffer *rb) {
    return atomic_load(&rb->head) == atomic_load(&rb->tail);
}

bool rb_check_abi(const RingBuffer *rb) {
    if (rb->abi_version != MONITOR_ABI_VERSION ||
        rb->slot_size    != (uint32_t)sizeof(SmoothedMetrics)) {
        fprintf(stderr,
            "[ring_buffer] ABI MISMATCH: segment has abi_version=%u "
            "slot_size=%u, we expect abi_version=%u slot_size=%zu. "
            "rebuild this consumer.\n",
            rb->abi_version, rb->slot_size,
            (unsigned)MONITOR_ABI_VERSION, sizeof(SmoothedMetrics));
        return false;
    }
    return true;
}