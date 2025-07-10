#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main() {
    printf("--> Attempting fileless execution via memfd_create...\n");

    // 1. 创建一个内存中的匿名文件
    int fd = memfd_create("payload", 0);
    if (fd == -1) {
        perror("memfd_create");
        return 1;
    }

    // 2. 向这个内存文件写入一个简单的shell脚本
    const char* script = "#!/bin/sh\necho '+++ This script was executed from memory! +++'\n";
    write(fd, script, strlen(script));

    // 3. 构造 /proc/self/fd/<fd> 路径并通过它来执行
    char path[256];
    sprintf(path, "/proc/self/fd/%d", fd);
    printf("      Executing from path: %s\n", path);
    
    // execve 会触发 EXEC 事件，其 filename 参数会是 /proc/self/fd/...
    execve(path, NULL, NULL);

    perror("execve failed");
    return 1;
}