#include <linux/limits.h>
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

static char *path_to_exe(pid_t pid) {
    int err;

    char symlink_path[PATH_MAX];
    char executable_path[PATH_MAX];

    err = sprintf(symlink_path, "/proc/%d/exe", pid);
    if (err < 0) {
        return NULL;
    }

    err = readlink(symlink_path, executable_path, PATH_MAX);
    if (err) {
        return NULL;
    }

    return strdup(executable_path);
}

int main(int argc, char **argv) {
    int err;
    args_t args;
    pid_t tracee_pid;
    char *tracee_exe;
    int pipefd[2];

    err = parse_args(&args, argc, argv);
    if (err) {
        return 1;
    }

    if (args.pid == 0) {
        err = pipe(pipefd);
        if (err) {
            panic("error creating pipe: %s", strerror(errno));
        }

        pid_t pid = fork();
        if (pid < 0) {
            panic("error creating child process: %s", strerror(errno));
        }

        if (pid == 0) {
            close(pipefd[1]);

            char c;

            err = read(pipefd[0], &c, 1);
            if (err <= 0) {
                exit(1);
            }

            close(pipefd[0]);

            err = execv(args.args[0], args.args);
            if (err) {
                panic("error executing");
            }
        } else {
            close(pipefd[0]);
            tracee_pid = pid;
        }
    } else {
        tracee_pid = args.pid;
    }

    if (args.pid == 0) {
        tracee_exe = args.args[0];
    } else {
        tracee_exe = path_to_exe(args.pid);
        if (!tracee_exe) {
            panic("error getting path to tracee's executable file");
        }
    }

    struct profiler_bpf *skel = profiler_bpf__open_and_load();
    if (!skel) {
        panic("error opening skeleton: %s", strerror(errno));
    }

    for (int i = 0; i < args.nfuncs; i++) {
        LIBBPF_OPTS(
            bpf_uprobe_opts,
            uprobe_opts,
            .func_name = args.funcs[i],
            .retprobe = false,
            .bpf_cookie = i
        );

        struct bpf_link *link = bpf_program__attach_uprobe_opts(
            skel->progs.uprobe, tracee_pid, tracee_exe, 0, &uprobe_opts
        );

        if (!link) {
            panic("error attaching uprobe: %s", strerror(errno));
        }
    }

    for (int i = 0; i < args.nfuncs; i++) {
        LIBBPF_OPTS(
            bpf_uprobe_opts,
            uretprobe_opts,
            .func_name = args.funcs[i],
            .retprobe = true,
            .bpf_cookie = i
        );

        struct bpf_link *link = bpf_program__attach_uprobe_opts(
            skel->progs.uretprobe, tracee_pid, tracee_exe, 0, &uretprobe_opts
        );

        if (!link) {
            panic("error attaching uretprobe: %s", strerror(errno));
        }
    }

    struct ring_buffer *rb = ring_buffer__new(
        bpf_map__fd(skel->maps.event_rb), event_callback, &args, NULL
    );

    if (!rb) {
        panic("error creating ring buffer: %s", strerror(errno));
    }

    if (args.pid == 0) {
        char c;
        err = write(pipefd[1], &c, 1);
        if (err < 0) {
            panic("error writing to pipe");
        }

        close(pipefd[1]);
    }

    while (1) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    profiler_bpf__destroy(skel);
}
