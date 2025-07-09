// command_injection.c
#include <unistd.h>

int main() {
    // 触发命令注入检测
    char *cmd = "/bin/bash";
    char *args[] = {"bash", "-c", "echo 'Hello from injected shell'", NULL};
    execv(cmd, args);
    return 0;
}