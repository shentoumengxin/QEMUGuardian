// fileless_exec.c
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main() {
    int fd = memfd_create("payload", 0);
    if (fd == -1) {
        perror("memfd_create");
        return 1;
    }

    const char* script = "#!/bin/sh\necho 'Fileless execution successful!'\n";
    write(fd, script, strlen(script));

    char path[256];
    sprintf(path, "/proc/self/fd/%d", fd);

    execl(path, path, NULL);

    return 0;
}