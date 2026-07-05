#include <stdio.h>

struct foo {
    int a;
    int b;
};

__attribute__((noinline))
static int add_values(int a, int b)
{
    return a + b;
}

int main(void)
{
    struct foo f = {
        .a = 1,
        .b = 2,
    };
    struct foo *p = &f;
    struct foo sa[3] = {
        { .a = 1, .b = 2 },
        { .a = 3, .b = 4 },
        { .a = 5, .b = 6 },
    };
    struct foo *psa = sa;

    printf("target: p=%p\n", p);
    printf("target: p->a=%d\n", p->a);
    printf("target: p->b=%d\n", p->b);
    printf("target: psa=%p\n", psa);
    printf("target: psa[0].a=%d\n", psa[0].a);
    printf("target: psa[0].b=%d\n", psa[0].b);
    printf("target: psa[1].a=%d\n", psa[1].a);
    printf("target: psa[1].b=%d\n", psa[1].b);
    printf("target: psa[2].a=%d\n", psa[2].a);
    printf("target: psa[2].b=%d\n", psa[2].b);

    volatile int x = 0;
    for (int i = 0; i < 3; i++) {
        x = add_values(x, i);
    }
    printf("target: x=%d\n", x);
    return 0;
}
