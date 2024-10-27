#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wait.h>

#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <sys/syscall.h>
#include <syscall.h>

#include "sample.skel.h"

typedef uint32_t u32;
typedef uint64_t u64;

#define panic(fmt, ...)                                                        \
    do {                                                                       \
        printf(fmt "\n", ##__VA_ARGS__);                                       \
        exit(1);                                                               \
    } while (0)

int should_exit = 0;

static int perf_event_open(
    struct perf_event_attr *attr,
    pid_t pid,
    int cpu,
    int group_fd,
    unsigned int flags
) {
    return syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void report_address(void *address) {
    if (address) {
        printf("%p\n", address);
    }
}

static void report(u64 *stack, u64 count) {
    printf("\n-----STACK-TRACE-----\n");
    printf("COUNT: %lu\n", count);

    for (int i = PERF_MAX_STACK_DEPTH - 1; i >= 0; i--) {
        report_address((void *)stack[i]);
    }
}

static void interrupt_handler() {
    should_exit = 1;
}

static void
report_stack_traces(struct bpf_map *stacks, struct bpf_map *counts) {
    int err;

    int key = 0;
    int next_key = 0;

    u64 stack[PERF_MAX_STACK_DEPTH];
    u64 count;

    while (!bpf_map__get_next_key(stacks, &key, &next_key, sizeof(u32))) {
        err = bpf_map__lookup_elem(
            stacks,
            &next_key,
            sizeof(u32),
            stack,
            sizeof(u64) * PERF_MAX_STACK_DEPTH,
            0
        );

        if (err) {
            panic("err");
        }

        bpf_map__lookup_elem(
            counts, &next_key, sizeof(u32), &count, sizeof(u64), 0
        );

        report(stack, count);

        key = next_key;
    }
}

int main(int argc, char **argv) {
    int err;

    struct sample_bpf *skel = sample_bpf__open_and_load();
    if (!skel) {
        panic("error opening/loading skeleton");
    }

    signal(SIGINT, interrupt_handler);

    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .sample_freq = 100,
        .freq = 1,
        .config = PERF_COUNT_SW_CPU_CLOCK,
        .size = sizeof(attr),
    };

    int pipefd[2];

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

        err = execvp(argv[1], argv + 1);
        if (err) {
            panic("error executing: %s", strerror(errno));
        }
    }

    int pfd = perf_event_open(&attr, pid, -1, -1, 0);
    if (pfd < 0) {
        panic("perf_event_open: %s", strerror(errno));
    }

    skel->links.capture_stack = bpf_program__attach_perf_event(
        skel->progs.capture_stack, pfd
    );

    if (!skel->links.capture_stack) {
        panic("error attaching to perf event: %s", strerror(errno));
    }

    char c;
    err = write(pipefd[1], &c, 1);
    if (err <= 0) {
        panic("error writing to pipe: %s", strerror(errno));
    }

    int status;

    while (!should_exit) {
        err = waitpid(pid, &status, 0);
        if (err < 0) {
            if (errno == EINTR) {
                continue;
            }

            panic("error waiting for child: %s", strerror(errno));
        }

        if (WIFEXITED(status)) {
            break;
        }
    }

    report_stack_traces(skel->maps.stacks, skel->maps.counts);

    sample_bpf__destroy(skel);
}
