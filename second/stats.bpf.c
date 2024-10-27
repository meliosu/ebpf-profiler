#include <limits.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "stats.common.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, sample_key_t);
    __type(value, sample_value_t);
    __uint(max_entries, 4096);
} samples SEC(".maps");

SEC("uprobe/...")
int at_entry(void *ctx) {
    int tid = bpf_get_current_pid_tgid();
    int cookie = bpf_get_attach_cookie(ctx);
    int now = bpf_ktime_get_ns();

    sample_key_t key = {
        .tid = tid,
        .cookie = cookie,
    };

    sample_value_t *value = bpf_map_lookup_elem(&samples, &key);

    if (!value) {
        sample_value_t inserted = {
            .min = ULONG_MAX,
            .max = 0,
            .count = 0,
            .time = 0,
            .beg = now,
        };

        bpf_map_update_elem(&samples, &key, &inserted, BPF_NOEXIST);
    } else {
        value->beg = now;
    }

    return 0;
}

SEC("uretprobe/...")
int at_exit(void *ctx) {
    int tid = bpf_get_current_pid_tgid();
    int cookie = bpf_get_attach_cookie(ctx);
    int now = bpf_ktime_get_ns();

    sample_key_t key = {
        .tid = tid,
        .cookie = cookie,
    };

    sample_value_t *value = bpf_map_lookup_elem(&samples, &key);
    if (!value) {
        return 0;
    }

    int duration = now - value->beg;

    value->time += duration;
    value->count += 1;

    if (value->min > duration) {
        value->min = duration;
    }

    if (value->max < duration) {
        value->max = duration;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
