#ifndef SLIDING_WINDOW_H
#define SLIDING_WINDOW_H

#include <stdint.h>

#define SWAG_CAPACITY 10  /* N=10 samples @ 50ms = 500ms window */

typedef struct {
    double   buffer[SWAG_CAPACITY];
    int      head;
    int      count;
    double   run_sum;
    uint32_t push_count;  /* tracks pushes for periodic FP drift recompute */
} SlidingWindow;

void   sw_init(SlidingWindow *sw);
void   sw_push(SlidingWindow *sw, double sample);
double sw_mean(const SlidingWindow *sw);

#endif /* SLIDING_WINDOW_H */
