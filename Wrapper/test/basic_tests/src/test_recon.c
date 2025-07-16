#include <stdio.h>
#include <unistd.h>
#include <fcntl.h> 

int main() {
    char buf[1024];
    ssize_t len;

    printf("--> Performing reconnaissance by explicitly calling readlinkat on /proc/self/exe...\n");

    len = readlinkat(AT_FDCWD, "/proc/self/cwd", buf, sizeof(buf) - 1);
    
    if (len != -1) {
        buf[len] = '\0';
        printf("      /proc/self/cwd points to: %s\n", buf);
    } else {
        perror("      readlinkat failed");
    }

    printf("Test finished.\n");
    return 0;
}