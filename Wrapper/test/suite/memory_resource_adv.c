#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>

#define PAGE_SIZE 4096

void print_stage(const char* message) {
    printf("\n--- [STAGE] %s ---\n", message);
}

// 修正后的信号处理器
void sig_handler_for_test(int signum) {
    printf("      (Caught signal %d, as expected. Exiting test gracefully.)\n", signum);
    // 直接退出，以防止因重复执行错误指令而导致的无限循环
    exit(0); 
}

int main(int argc, char *argv[]) {
    printf("======== Starting Advanced Memory & Resource Attack Suite ========\n");

    // --- 疑似有害但实则无害的操作 ---
    print_stage("Suspicious but Benign Operations");
    printf("--> [S.1] Hardening memory by making it read-only with mprotect...\n");
    void* ro_mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ro_mem != MAP_FAILED) {
        mprotect(ro_mem, PAGE_SIZE, PROT_READ); // 合法使用mprotect
    }

    printf("--> [S.2] Creating a moderate number of child processes (15)...\n");
    for (int i=0; i<15; ++i) {
        if (fork() == 0) exit(0);
    }
    while(wait(NULL) > 0);

    // --- 真正有害的操作 ---
    print_stage("Truly Malicious Operations");
    printf("--> [M.1] Attack: Making memory executable (PROT_EXEC)...\n");
    void* exec_mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (exec_mem != MAP_FAILED) {
        mprotect(exec_mem, PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC);
    }
    
    printf("--> [M.2] Attack: Simulating data exfiltration via file I/O...\n");
    char small_buf[10];
    char large_buf[16384];
    memset(large_buf, 'Z', sizeof(large_buf));
    int temp_fd = open("/tmp/exfil.dat", O_CREAT | O_RDWR | O_TRUNC, 0644);
    if (temp_fd != -1) {
        read(temp_fd, small_buf, sizeof(small_buf));
        lseek(temp_fd, 0, SEEK_SET);
        write(temp_fd, large_buf, sizeof(large_buf));
        close(temp_fd);
    }

    // --- 资源耗尽 (可选，移到信号测试之前，因为它不会退出) ---
    if (argc > 1 && strcmp(argv[1], "--fork-bomb") == 0) {
        print_stage("Resource Exhaustion (Fork Bomb)");
        printf("WARNING: Fork bomb activated!\n");
        while(1) { fork(); }
    }

    // --- 异常信号处理 (放在最后，因为它会退出程序) ---
    print_stage("Abnormal Signal Handling");
    
    printf("--> [M.3] Attack: Intentionally causing SIGILL (Illegal Instruction)...\n");
    signal(SIGILL, sig_handler_for_test);
    // 在一些架构上，ud2是明确的非法指令
    // __asm__("ud2");

    // 由于信号处理器会退出，这部分代码将不会被执行
    printf("\n======== This line should not be reached. ========\n");
    return 1;
}
