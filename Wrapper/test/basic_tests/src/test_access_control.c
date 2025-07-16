#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    printf("Attempting to trigger Access Control violations...\n");

    printf("--> Attempting setuid(0)...\n");
    if (setuid(0) == -1) {
        perror("      setuid(0) failed (as expected on non-root run)");
    }

    printf("--> Attempting to open /etc/shadow...\n");
    int fd1 = open("/etc/shadow", O_RDONLY);
    if (fd1 == -1) {
        perror("      open(/etc/shadow) failed (as expected)");
    } else {
        close(fd1);
    }

    printf("--> Attempting path traversal with ../../etc/passwd...\n");
    int fd2 = open("../../etc/passwd", O_RDONLY);
    if (fd2 == -1) {
        perror("      open(../../etc/passwd) failed (as expected)");
    } else {
        close(fd2);
    }
    
    printf("Test finished.\n");
    return 0;
}