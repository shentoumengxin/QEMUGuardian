#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h> // <--- 新增: 包含了 wait()

void print_stage(const char* message) {
    printf("\n--- [STAGE] %s ---\n", message);
}

int main() {
    printf("======== Starting Advanced Recon & PrivEsc Suite ========\n");
    char buf[1024];

    print_stage("Benign Operations");
    printf("--> [0.1] Writing to a temporary log file...\n");
    int temp_fd = open("/tmp/suite1_log.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (temp_fd != -1) {
        write(temp_fd, "Benign log entry.\n", 18);
        close(temp_fd);
    }

    print_stage("Suspicious but Benign Operations");
    printf("--> [S.1] Reading non-sensitive procfs file /proc/self/stat...\n");
    open("/proc/self/stat", O_RDONLY);
    
    printf("--> [S.2] Attempting to setuid to a non-root user (1001)...\n");
    setuid(1001);

    print_stage("Truly Malicious Operations");
    printf("--> [M.1] Recon: Reading /proc/self/maps for memory layout...\n");
    // 修正: 检查readlinkat的返回值，避免使用未初始化的buf
    ssize_t len = readlinkat(AT_FDCWD, "/proc/self/maps", buf, sizeof(buf) - 1);
    if (len > 0) buf[len] = '\0';
    
    printf("--> [M.2] Attack: Path Traversal to read /etc/hostname...\n");
    open("../../etc/hostname", O_RDONLY);

    printf("--> [M.3] Attack: Attempting to READ /etc/shadow...\n");
    open("/etc/shadow", O_RDONLY);
    
    printf("--> [M.4] Attack: Attempting to WRITE to /etc/passwd...\n");
    open("/etc/passwd", O_WRONLY | O_APPEND);

    printf("--> [M.5] Attack: Attempting setuid(0) to gain root access...\n");
    setuid(0);

    print_stage("Process Injection via Ptrace");
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        // 修正: 使用 execlp 可以让系统在PATH中查找'id'，更健壮
        execlp("id", "id", NULL);
        exit(1); // 如果execlp失败，则退出
    } else {
        wait(NULL);
        printf("--> [M.6] Attack: Attaching to child process with ptrace...\n");
        ptrace(PTRACE_ATTACH, child, NULL, NULL);
        sleep(1);
        ptrace(PTRACE_DETACH, child, NULL, NULL);
    }

    printf("\n======== Suite Finished ========\n");
    return 0;
}
