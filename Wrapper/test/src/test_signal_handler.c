#include <stdio.h>
#include <signal.h>
#include <stdlib.h>

void segmentation_fault_handler(int signum) {
    printf("\n      Custom SIGSEGV handler caught signal %d. Program will now exit gracefully.\n", signum);
    exit(0);
}

int main() {
    signal(SIGSEGV, segmentation_fault_handler);
    printf("--> Custom SIGSEGV handler registered.\n");

    printf("      Intentionally causing a segmentation fault...\n");
    int *ptr = NULL;
    *ptr = 1; 

    printf("This line should not be reached.\n");
    return 1;
}