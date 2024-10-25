#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "profiler.common.h"

#define INLINE static __attribute__((always_inline))

#define RB_SIZE (256 * 1024)
#define NFUNCS 16

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RB_SIZE);
} event_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __type(key, __u32);
    __type(value, entry_t[NFUNCS]);
    __uint(max_entries, 0);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} event_ts SEC(".maps");

INLINE int submit_flags() {
    int rb_size = bpf_ringbuf_query(&event_rb, BPF_RB_AVAIL_DATA);
    int threshold = RB_SIZE / 4;
    return rb_size >= threshold ? BPF_RB_FORCE_WAKEUP : 0;
}

SEC("uprobe/...")
int uprobe(void *ctx) {
    unsigned int cookie = bpf_get_attach_cookie(ctx) >> 32;

    bpf_printk("uprobe cookie: %d", cookie);

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    entry_t *entries = bpf_task_storage_get(&event_ts, task, NULL,
                                            BPF_LOCAL_STORAGE_GET_F_CREATE);

    if (!entries) {
        return 0;
    }

    if (cookie >= NFUNCS) {
        return 0;
    }

    entries[cookie].start = bpf_ktime_get_ns();

    return 0;
}

SEC("uretprobe/...")
int uretprobe(void *ctx) {
    unsigned int cookie = bpf_get_attach_cookie(ctx) >> 32;

    bpf_printk("uretprobe cookie: %d", cookie);

    struct task_struct *task = (void *)bpf_get_current_task_btf();
    entry_t *entries = bpf_task_storage_get(&event_ts, task, NULL, 0);

    if (!entries) {
        return 0;
    }

    if (cookie >= NFUNCS) {
        return 0;
    }

    unsigned long start = entries[cookie].start;

    if (start == 0) {
        return 0;
    }

    event_t *event = bpf_ringbuf_reserve(&event_rb, sizeof(*event), 0);

    if (!event) {
        return 0;
    }

    int tid = bpf_get_current_pid_tgid() >> 32;
    unsigned long end = bpf_ktime_get_ns();

    event->cookie = cookie;
    event->tid = tid;
    event->start = start;
    event->end = end;

    int flags = submit_flags();
    bpf_ringbuf_submit(event, flags);

    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
