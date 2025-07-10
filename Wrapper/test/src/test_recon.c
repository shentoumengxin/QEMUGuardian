#include <stdio.h>
#include <unistd.h>

int main() {
    char buf[1024];
    ssize_t len;

    printf("--> Performing reconnaissance by reading /proc/self/exe...\n");

    len = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len != -1) {
        buf[len] = '\0';
        printf("      /proc/self/exe points to: %s\n", buf);
    } else {
        perror("      readlink failed");
    }

    printf("Test finished.\n");
    return 0;
}