#include <stdio.h>
#include <string.h>

static int counter = 3;
int shared_total;

int add_numbers(int a, int b) { return a + b; }

int main(int argc, char **argv)
{
    char buf[64];
    snprintf(buf, sizeof buf, "hello from an RTP, argc=%d", argc);
    shared_total = add_numbers(counter, (int)strlen(buf));
    puts(buf);
    return shared_total > 0 ? 0 : 1;
}
