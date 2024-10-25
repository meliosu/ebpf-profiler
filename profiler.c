#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "args.h"
#include "profiler.common.h"
#include "profiler.skel.h"

#define panic(fmt, ...)                                                        \
    do {                                                                       \
        printf(fmt "\n", ##__VA_ARGS__);                                       \
        exit(1);                                                               \
    } while (0)

static void event_report(event_t *event, char **funcs) {
    printf("\n-----EVENT-----\n");
    printf("tid: %d\n", event->tid);
    printf("function: %s\n", funcs[event->cookie]);
    printf("time: %lu ns.\n", event->end - event->start);
    printf("-----------------\n");
}

static int event_callback(void *ctx, void *data, size_t data_sz) {
    args_t *args = ctx;
    event_t *events = data;

    for (int i = 0; i < data_sz / sizeof(event_t); i++) {
        event_report(&events[i], args->funcs);
    }

    return 0;
}

int main(int argc, char **argv) {
    int err;
    args_t args;

    err = parse_args(&args, argc, argv);
    if (err) {
        return 1;
    }

    struct profiler_bpf *skel = profiler_bpf__open_and_load();
    if (!skel) {
        panic("error opening skeleton: %s", strerror(errno));
    }

    for (int i = 0; i < args.nfuncs; i++) {
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = args.funcs[i],
                    .retprobe = false, .bpf_cookie = i);

        struct bpf_link *link = bpf_program__attach_uprobe_opts(
            skel->progs.uprobe, args.pid, args.exec, 0, &uprobe_opts);

        if (!link) {
            panic("error attaching uprobe: %s", strerror(errno));
        }
    }

    for (int i = 0; i < args.nfuncs; i++) {
        LIBBPF_OPTS(bpf_uprobe_opts, uretprobe_opts, .func_name = args.funcs[i],
                    .retprobe = true, .bpf_cookie = i);

        struct bpf_link *link = bpf_program__attach_uprobe_opts(
            skel->progs.uretprobe, args.pid, args.exec, 0, &uretprobe_opts);

        if (!link) {
            panic("error attaching uretprobe: %s", strerror(errno));
        }
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.event_rb),
                                              event_callback, &args, NULL);

    if (!rb) {
        panic("error creating ring buffer: %s", strerror(errno));
    }

    while (1) {
        ring_buffer__poll(rb, 100);
        /*if (err) {*/
        /*    panic("error polling ring buffer: %s", strerror(errno));*/
        /*}*/
    }

    ring_buffer__free(rb);
    profiler_bpf__destroy(skel);
}
