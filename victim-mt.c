#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

#define NUM_THREADS 5
#define NOINLINE __attribute__((noinline))

NOINLINE void uprobed_fn1() {
    printf("function 1...\n");
}

NOINLINE void uprobed_fn2() {
    printf("function 2...\n");
}

void *thread(void *_) {
    while (1) {
        uprobed_fn1();
        sleep(1);

        uprobed_fn2();
        sleep(1);
    }
}

int main() {
    pthread_t tids[NUM_THREADS];

    printf("[%d]\n", getpid());

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&tids[i], NULL, thread, NULL);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(tids[i], NULL);
    }
}
