#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>

#define ONE_MB (1024 * 1024)
#define LARGE_ALLOC_PAGES 20000 
#define PAGE_SIZE 4096

int main() {
    printf("Attempting to trigger Memory Corruption signals...\n");

    printf("--> Mapping memory and making it executable...\n");
    void *mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap for mprotect failed");
    } else {
        if (mprotect(mem, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
            perror("      mprotect failed");
        } else {
            printf("      Memory at %p is now executable.\n", mem);
        }
    }
    
    printf("--> Attempting a very large mmap allocation...\n");
    void *large_mem = mmap(NULL, LARGE_ALLOC_PAGES * PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (large_mem == MAP_FAILED) {
        perror("      Large mmap failed (as it might on some systems)");
    } else {
        printf("      Successfully mapped %d pages.\n", LARGE_ALLOC_PAGES);
        munmap(large_mem, LARGE_ALLOC_PAGES * PAGE_SIZE);
    }

    printf("Test finished.\n");
    return 0;
}