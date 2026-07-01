#include <stdio.h>

__attribute__((noinline))
static int add_values(int a, int b)
{
    return a + b;
}

int main(void)
{
    volatile int x = 0;
    for (int i = 0; i < 3; i++) {
        x = add_values(x, i);
    }
    printf("target: x=%d\n", x);
    return 0;
}
