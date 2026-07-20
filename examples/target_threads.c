#include <pthread.h>
#include <stdio.h>
#include <unistd.h>

static volatile int worker_counter = 0;

__attribute__((noinline))
static void *worker(void *arg)
{
    (void)arg;
    for (;;) {
        worker_counter++;
        sleep(1);
    }
    return NULL;
}

int main(void)
{
    pthread_t tid;
    if (pthread_create(&tid, NULL, worker, NULL) != 0) {
        return 1;
    }

    printf("target_threads: worker thread created\n");

    for (;;) {
        sleep(1);
    }

    return 0;
}
