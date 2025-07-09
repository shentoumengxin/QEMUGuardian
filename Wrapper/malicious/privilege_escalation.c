// privilege_escalation.c
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    // 触发权限提升检测
    if (setuid(0) == -1) {
        perror("setuid failed");
    }

    // 触发敏感文件访问检测
    int fd = open("/etc/shadow", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /etc/shadow");
    } else {
        close(fd);
    }
    
    // 触发路径遍历检测
    fd = open("../../etc/passwd", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open ../../etc/passwd");
    } else {
        close(fd);
    }

    return 0;
}