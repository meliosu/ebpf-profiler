#ifndef STATS_ARGS_H
#define STATS_ARGS_H

#include <argp.h>
#include <stdlib.h>
#include <string.h>

#define KEY_FUNCTIONS 'f'

typedef struct {
    char **funcs;
    int nfuncs;
    char **args;
    int nargs;
} args_t;

static error_t parse_opts(int key, char *arg, struct argp_state *state) {
    args_t *args = (args_t *)state->input;

    switch (key) {
    case KEY_FUNCTIONS: {
        int nfuncs = 1;

        for (char *c = arg; *c != 0; c++) {
            if (*c == ',') {
                nfuncs++;
            }
        }

        char **funcs = (char **)malloc(nfuncs * sizeof(char *));

        int i = 0;
        char *tok = strtok(arg, ",");

        while (tok) {
            funcs[i++] = tok;
            tok = strtok(NULL, ",");
        }

        args->funcs = funcs;
        args->nfuncs = nfuncs;
        break;
    }

    case ARGP_KEY_ARG: {
        args->args = (char **)realloc(
            args->args, (args->nargs + 1) * sizeof(char *)
        );

        args->args[args->nargs++] = arg;
        break;
    }

    case ARGP_KEY_END: {
        if (!args->funcs) {
            argp_usage(state);
        }

        if (args->args) {
            args->args = (char **)realloc(
                args->args, (args->nargs + 1) * sizeof(char *)
            );

            args->args[args->nargs] = NULL;
        }

        break;
    }

    case ARGP_KEY_INIT: {
        args->funcs = NULL;
        args->nfuncs = 0;
        args->args = NULL;
        args->nargs = 0;
        break;
    }

    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static error_t argparse(args_t *args, int argc, char **argv) {
    struct argp_option opts[] = {
        {"functions",
         KEY_FUNCTIONS,
         "FN1,FN2,..",
         0,
         "list of functions to trace"},
        {0},
    };

    struct argp argp = {
        opts,
        parse_opts,
        0,
        "eBPF Profiler that records avg, min and max function execution time",
    };

    return argp_parse(&argp, argc, argv, 0, 0, args);
}

#endif /* STATS_ARGS_H */
