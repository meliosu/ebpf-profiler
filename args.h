#ifndef PROFILER_ARGS_H
#define PROFILER_ARGS_H

#include <argp.h>
#include <stdlib.h>
#include <string.h>

#define KEY_PID 'p'
#define KEY_EXEC 'e'
#define KEY_FUNCS 'f'

typedef struct {
    int pid;
    char *exec;
    int nfuncs;
    char **funcs;
} args_t;

static error_t parse_opts(int key, char *arg, struct argp_state *state) {
    args_t *args = (args_t *)state->input;

    switch (key) {
    case KEY_PID: {
        int pid = atoi(arg);

        if (!pid) {
            argp_error(state, "%s is not a valid pid", arg);
        }

        args->pid = pid;
        break;
    }

    case KEY_EXEC: {
        args->exec = arg;
        break;
    }

    case KEY_FUNCS: {
        int nfuncs = 1;

        for (char *c = arg; *c != 0; c++) {
            if (*c == ',') {
                nfuncs += 1;
            }
        }

        char **funcs = (char **)malloc(nfuncs * sizeof(char *));

        int i = 0;
        char *token = strtok(arg, ",");

        while (token) {
            funcs[i++] = token;
            token = strtok(NULL, ",");
        }

        args->funcs = funcs;
        args->nfuncs = nfuncs;
        break;
    }

    case ARGP_KEY_END: {
        if (args->pid == 0) {
            argp_error(state, "--pid is required");
        }

        if (args->exec == NULL) {
            argp_error(state, "--exec is required");
        }

        if (args->funcs == NULL) {
            argp_error(state, "--functions is required");
        }

        break;
    }

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static error_t parse_args(args_t *args, int argc, char **argv) {
    struct argp_option opts[] = {
        {"pid", KEY_PID, "PID", 0, "pid of the process to trace"},
        {"exec", KEY_EXEC, "FILE", 0, "path to executable file of the process"},
        {"functions", KEY_FUNCS, "F1,F2,..", 0, "list of functions to trace"},
        {0}};

    struct argp argp = {
        opts,
        parse_opts,
        0,
        "eBPF profiler implemented through uprobes",
    };

    args->pid = 0;
    args->exec = NULL;
    args->funcs = NULL;

    return argp_parse(&argp, argc, argv, 0, 0, args);
}

#endif /* PROFILER_ARGS_H */
