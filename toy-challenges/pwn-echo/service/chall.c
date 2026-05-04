#include <stdio.h>
#include <unistd.h>

// Tiny binary; the optimizer doesn't naturally produce a `pop rdi; ret` for
// ROP. Embed one explicitly via a naked helper so the gadget exists in .text.
// Never called — `used` prevents the linker from stripping it.
void __attribute__((naked, used)) _gadget(void) {
    __asm__("pop %rdi; ret");
}

void echo(void) {
    char buf[64];
    write(1, "> ", 2);
    int n = read(0, buf, 256);
    if (n > 0) write(1, buf, n);
}

int main(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    puts("echo server v0.1");
    echo();
    return 0;
}
