#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main() {
    printf("--> Attempting fileless execution via memfd_create...\n");

    int fd = memfd_create("payload", 0);
    if (fd == -1) {
        perror("memfd_create");
        return 1;
    }

    const char* script = "#!/bin/sh\necho '+++ This script was executed from memory! +++'\n";
    write(fd, script, strlen(script));

    char path[256];
    sprintf(path, "/proc/self/fd/%d", fd);
    printf("      Executing from path: %s\n", path);
    
    execve(path, NULL, NULL);

    perror("execve failed");
    return 1;
}