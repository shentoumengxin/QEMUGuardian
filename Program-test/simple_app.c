// test_app.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/wait.h>


void do_file_ops() {
    int fd = open("demo.txt", O_CREAT|O_RDWR, 0644);
    if (fd < 0) { perror("open"); return; }
    write(fd, "Hello QEMU!\n", 12);
    lseek(fd, 0, SEEK_SET);
    char buf[32] = {};
    read(fd, buf, sizeof(buf));
    printf("READ: %s", buf);
    close(fd);
}

void do_memory_ops() {
    char *p = malloc(64);
    strcpy(p, "This is a test of strcpy overflow\0");
    printf("MALLOC/STRCPY OK: %s\n", p);
    free(p);

    // mmap + munmap
    void *m = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (m != MAP_FAILED) {
        strcpy((char*)m, "Memory mapped string\n");
        printf("%s", (char*)m);
        munmap(m, 4096);
    }
}

void do_process_ops() {
    pid_t pid = fork();
    if (pid == 0) {
        // child: exec /bin/true
        execl("/bin/true", "true", NULL);
        _exit(1);
    } else if (pid > 0) {
        wait(NULL);
        printf("FORK+EXECVE OK (child=%d)\n", pid);
    }
}

void do_network_ops() {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) { perror("socket"); return; }
    struct sockaddr_in srv = {
        .sin_family = AF_INET,
        .sin_port = htons(80),
        .sin_addr = { .s_addr = inet_addr("93.184.216.34") } // example.com
    };
    connect(s, (struct sockaddr*)&srv, sizeof(srv));
    const char *req = "HEAD / HTTP/1.0\r\n\r\n";
    send(s, req, strlen(req), 0);
    char rbuf[128] = {};
    recv(s, rbuf, sizeof(rbuf)-1, 0);
    printf("RECV HEAD: %.32s...\n", rbuf);
    close(s);
}

void do_dlopen() {
    void *h = dlopen("libm.so.6", RTLD_LAZY);
    if (h) {
        double (*cosfptr)(double) = dlsym(h, "cos");
        printf("DLOPEN+DSYM: cos(0)=%.2f\n", cosfptr(0.0));
        dlclose(h);
    }
}

int main() {
    printf("=== Starting test_app ===\n");
    do_file_ops();
    do_memory_ops();
    do_process_ops();
    do_network_ops();
    do_dlopen();
    printf("=== test_app done ===\n");
    return 0;
}
