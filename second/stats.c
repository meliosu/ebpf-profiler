#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
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

int main(int argc, char **argv) {
    int err;
    args_t args;

    err = argparse(&args, argc, argv);
    if (err) {
        panic("error parsing args");
    }

    char *exe = resolve(args.args[0]);
    if (!exe) {
        panic("error finding executable");
    }

    struct stats_bpf *skel = stats_bpf__open_and_load();
    if (!skel) {
        panic("error opening/loading skeleton: %s", strerror(errno));
    }

    pid_t pid = fork();
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

        err = execvp(args.args[0], args.args);
        if (err) {
            panic("error executing: %s", strerror(errno));
        }
    }

    struct bpf_link *link;

    for (int i = 0; i < args.nfuncs; i++) {
        func_t *func = &args.funcs[i];
        char *symbol = func->symbol;
        char *object = func->object ?: exe;

        LIBBPF_OPTS(
            bpf_uprobe_opts,
            opts,
            .bpf_cookie = i,
            .retprobe = false,
            .func_name = symbol,
        );

        link = bpf_program__attach_uprobe_opts(
            skel->progs.at_entry, pid, object, 0, &opts
        );

        if (!link) {
            panic("error attaching uprobe: %s", strerror(errno));
        }
    }

    for (int i = 0; i < args.nfuncs; i++) {
        func_t *func = &args.funcs[i];
        char *symbol = func->symbol;
        char *object = func->object ?: exe;

        LIBBPF_OPTS(
            bpf_uprobe_opts,
            opts,
            .bpf_cookie = i,
            .retprobe = true,
            .func_name = symbol
        );

        link = bpf_program__attach_uprobe_opts(
            skel->progs.at_exit, pid, object, 0, &opts
        );

        if (!link) {
            panic("error attaching uprobe: %s", strerror(errno));
        }
    }

    signal(SIGINT, sighandler);

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

    while (!bpf_map__get_next_key(
        skel->maps.samples, &key, &next_key, sizeof(sample_key_t)
    )) {
        sample_value_t value;

        err = bpf_map__lookup_elem(
            skel->maps.samples,
            &next_key,
            sizeof(sample_key_t),
            &value,
            sizeof(sample_value_t),
            0
        );

        if (err) {
            panic("error looking up element in a map: %s", strerror(errno));
        }

        report(&args, &next_key, &value);

        key = next_key;
    }

    stats_bpf__destroy(skel);
}
