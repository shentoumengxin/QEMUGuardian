#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Attempting to execute /bin/bash...\n");

    char *args[] = {"/bin/bash", "-c", "echo '+++ This shell was executed by the test program +++'", NULL};
    execv("/bin/bash", args);

    perror("execv failed");
    return 1;
}