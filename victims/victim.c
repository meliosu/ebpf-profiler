#include <stdio.h>
#include <unistd.h>

#define NOINLINE __attribute__((noinline))

NOINLINE void uprobed_fn1() {
    printf("function 1...\n");
}

NOINLINE void uprobed_fn2() {
    printf("function 2...\n");
}

int main() {
    printf("[%d]\n", getpid());

    while (1) {
        sleep(1);
        uprobed_fn1();

        sleep(1);
        uprobed_fn2();
    }
}
