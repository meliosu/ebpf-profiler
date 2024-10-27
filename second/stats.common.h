#ifndef STATS_COMMON_H
#define STATS_COMMON_H

typedef unsigned long long u64;

typedef struct {
    int tid;
    int cookie;
} sample_key_t;

typedef struct {
    u64 time;
    u64 count;
    u64 max;
    u64 min;
    u64 beg;
} sample_value_t;

#endif /* STATS_COMMON_H */
