#include "sliding_window.h"
#include <string.h>

void sw_init(SlidingWindow *sw) {
    memset(sw->buffer, 0, sizeof(sw->buffer));
    sw->head       = 0;
    sw->count      = 0;
    sw->run_sum    = 0.0;
    sw->push_count = 0;
}

void sw_push(SlidingWindow *sw, double sample) {
    if (sw->count == SWAG_CAPACITY) {
        /* evict oldest: subtract it from running sum */
        sw->run_sum -= sw->buffer[sw->head];
    } else {
        sw->count++;
    }
    sw->buffer[sw->head] = sample;
    sw->run_sum         += sample;
    sw->head             = (sw->head + 1) % SWAG_CAPACITY;

    /* Periodic exact recompute to prevent floating-point drift.
     * After SWAG_CAPACITY^2 pushes (100 for N=10), accumulated rounding
     * errors in run_sum can cause sw_mean() to diverge from the true mean.
     * Recomputing from scratch every N^2 pushes costs one full buffer
     * scan every 100 intervals (every 5 seconds at 50ms), negligible. */
    if (++sw->push_count >= (uint32_t)(SWAG_CAPACITY * SWAG_CAPACITY)) {
        sw->push_count = 0;
        double exact = 0.0;
        for (int j = 0; j < sw->count; j++)
            exact += sw->buffer[j];
        sw->run_sum = exact;
    }
}

double sw_mean(const SlidingWindow *sw) {
    if (sw->count == 0) return 0.0;
    return sw->run_sum / sw->count;
}
