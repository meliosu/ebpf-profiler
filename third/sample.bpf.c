#include <linux/bpf.h>
#include <linux/perf_event.h>

#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(__u64));
    __uint(max_entries, 4096);
} stacks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 4096);
} counts SEC(".maps");

SEC("perf_event")
int capture_stack(void *ctx) {
    int stackid = bpf_get_stackid(
        ctx, &stacks, BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP
    );

    if (stackid < 0) {
        return 0;
    }

    unsigned long *count = bpf_map_lookup_elem(&counts, &stackid);

    if (!count) {
        unsigned long one = 1;
        bpf_map_update_elem(&counts, &stackid, &one, BPF_ANY);
    } else {
        *count += 1;
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
