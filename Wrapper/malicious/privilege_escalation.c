// privilege_escalation.c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    if (setuid(0) == -1) {
        perror("setuid failed");
    }

    int fd = open("/etc/shadow", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /etc/shadow");
    } else {
        close(fd);
    }
    
    fd = open("../../etc/passwd", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open ../../etc/passwd");
    } else {
        close(fd);
    }

    return 0;
}