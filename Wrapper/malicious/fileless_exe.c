// fileless_exec.c
#define _GNU_SOURCE
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main() {
    // 创建一个内存文件描述符
    int fd = memfd_create("payload", 0);
    if (fd == -1) {
        perror("memfd_create");
        return 1;
    }

    // 写入 shell 脚本作为 payload
    const char* script = "#!/bin/sh\necho 'Fileless execution successful!'\n";
    write(fd, script, strlen(script));

    // 构造执行路径 /proc/self/fd/<fd>
    char path[256];
    sprintf(path, "/proc/self/fd/%d", fd);

    // 触发 EXEC 检测
    execl(path, path, NULL);

    return 0;
}