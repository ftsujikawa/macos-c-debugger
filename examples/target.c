#include <stdio.h>

int main(void)
{
    volatile int x = 0;
    for (int i = 0; i < 3; i++) {
        x += i;
    }
    printf("target: x=%d\n", x);
    return 0;
}
