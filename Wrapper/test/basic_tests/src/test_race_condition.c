#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

void *map;
int stop = 0;

void *madvise_thread(void *arg) {
    printf("      [Thread 2] madvise thread started.\n");
    for (int i = 0; i < 20000; i++) { 
        madvise(map, 100, MADV_DONTNEED);
    }
    stop = 1;
    return NULL;
}

int main() {
    pthread_t pth;
    
    map = mmap(NULL, 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (map == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    strcpy(map, "Hello World");

    int fd = open("/proc/self/mem", O_RDWR);
    if (fd == -1) {
        perror("open /proc/self/mem");
        return 1;
    }

    printf("--> Starting race condition test (madvise vs /proc/self/mem write)...\n");
    pthread_create(&pth, NULL, madvise_thread, NULL);

    printf("      [Thread 1] write thread started.\n");
    while(!stop) {
        lseek(fd, (off_t)map, SEEK_SET);
        write(fd, "dirtycow", 8);
    }
    
    pthread_join(pth, NULL);
    close(fd);
    printf("Test finished.\n");
    return 0;
}