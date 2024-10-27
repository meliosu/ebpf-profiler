#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>

#include "args.h"
#include "stats.common.h"
#include "stats.skel.h"

#define panic(fmt, ...)                                                        \
    do {                                                                       \
        printf(fmt "\n", ##__VA_ARGS__);                                       \
        exit(1);                                                               \
    } while (0)

int should_exit = 0;

static void sighandler() {
    should_exit = 1;
}

static char *which(char *name) {
    char *path = getenv("PATH");
    if (!path) {
        return NULL;
    }

    path = strdup(path);

    char exe[PATH_MAX];
    for (char *dir = strtok(path, ":"); dir != NULL; dir = strtok(NULL, ":")) {
        snprintf(exe, PATH_MAX, "%s/%s", dir, name);

        struct stat statbuf;
        if (!fstatat(AT_FDCWD, exe, &statbuf, 0)) {
            free(path);
            return strdup(exe);
        }
    }

    free(path);
    return NULL;
}

static char *resolve(char *name) {
    for (char *c = name; *c != 0; c++) {
        if (*c == '/') {
            return name;
        }
    }

    return which(name);
}

static struct bpf_link *attach_uprobe(
    struct bpf_program *program,
    pid_t pid,
    char *object,
    char *symbol,
    int retprobe,
    int cookie
) {
    LIBBPF_OPTS(
        bpf_uprobe_opts,
        opts,
        .func_name = symbol,
        .retprobe = retprobe,
        .bpf_cookie = cookie
    );

    return bpf_program__attach_uprobe_opts(program, pid, object, 0, &opts);
}

static void
attach_uprobes(args_t *args, struct stats_bpf *skel, pid_t pid, char *exe) {
    struct bpf_link *link;

    for (int i = 0; i < args->nfuncs; i++) {
        char *symbol = args->funcs[i].symbol;
        char *object = args->funcs[i].object ?: exe;

        link = attach_uprobe(
            skel->progs.at_entry, pid, object, symbol, false, i
        );

        if (!link) {
            panic("error attaching uprobe: %s", strerror(errno));
        }
    }

    for (int i = 0; i < args->nfuncs; i++) {
        char *symbol = args->funcs[i].symbol;
        char *object = args->funcs[i].object ?: exe;

        link = attach_uprobe(skel->progs.at_exit, pid, object, symbol, true, i);

        if (!link) {
            panic("error attaching uprobe: %s", strerror(errno));
        }
    }
}

static void report(args_t *args, sample_key_t *key, sample_value_t *value) {
    printf(
        "%-8d %-16s %-8llu %-8.1f %-8.1f %-8.1f\n",
        key->tid,
        args->funcs[key->cookie].symbol,
        value->count,
        (float)value->min / 1000.0,
        (float)value->max / 1000.0,
        (float)value->time / ((float)value->count * 1000.0)
    );
}

static void observe_child(struct stats_bpf *skel, args_t *args) {
    pid_t pid;
    int err;

    char *exe = resolve(args->args[0]);
    if (!exe) {
        panic("error finding executable");
    }

    pid = fork();
    if (pid < 0) {
        panic("error creating child: %s", strerror(errno));
    }

    if (pid == 0) {
        int sig;
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, SIGUSR1);
        sigprocmask(SIG_BLOCK, &set, NULL);

        err = sigwait(&set, &sig);
        if (err) {
            panic("error waiting for signal: %s", strerror(err));
        }

        sigprocmask(SIG_UNBLOCK, &set, NULL);

        err = execvp(args->args[0], args->args);
        if (err) {
            panic("error executing: %s", strerror(errno));
        }
    }

    attach_uprobes(args, skel, pid, exe);

    err = kill(pid, SIGUSR1);
    if (err) {
        panic("error sending signal to child: %s", strerror(errno));
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
}

static void observe_system(struct stats_bpf *skel, args_t *args) {
    attach_uprobes(args, skel, -1, NULL);

    while (!should_exit) {
        pause();
    }
}

static void print_summary(args_t *args, struct bpf_map *samples) {
    int err;

    printf(
        "\n%-8s %-16s %-8s %-8s %-8s %-8s\n",
        "thread",
        "function",
        "cnt",
        "min",
        "max",
        "avg"
    );

    sample_key_t key = {0};
    sample_key_t next_key;

    while (
        !bpf_map__get_next_key(samples, &key, &next_key, sizeof(sample_key_t))
    ) {
        sample_value_t value;

        err = bpf_map__lookup_elem(
            samples,
            &next_key,
            sizeof(sample_key_t),
            &value,
            sizeof(sample_value_t),
            0
        );

        if (err) {
            panic("error looking up element in a map: %s", strerror(errno));
        }

        report(args, &next_key, &value);

        key = next_key;
    }
}

int main(int argc, char **argv) {
    int err;
    args_t args;

    err = argparse(&args, argc, argv);
    if (err) {
        panic("error parsing args");
    }

    struct stats_bpf *skel = stats_bpf__open_and_load();
    if (!skel) {
        panic("error opening/loading skeleton: %s", strerror(errno));
    }

    signal(SIGINT, sighandler);

    if (args.args) {
        observe_child(skel, &args);
    } else {
        observe_system(skel, &args);
    }

    print_summary(&args, skel->maps.samples);

    stats_bpf__destroy(skel);
}
