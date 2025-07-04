#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

// 宏，用于字节序转换
#define s2n(s, a) ((*(a) = (unsigned char)(((s) >> 8) & 0xff)), (*((a)+1) = (unsigned char)((s) & 0xff)))
#define n2s(a, s) ((s) = ((unsigned short)(*(a))) << 8 | (unsigned short)(*((a)+1)))

// 管道文件描述符
int client_to_server_pipe[2];
int server_to_client_pipe[2];

#define HEARTBEAT_REQUEST 1
#define HEARTBEAT_RESPONSE 2

// 模拟的服务器进程
void vulnerable_server_process() {
    close(client_to_server_pipe[1]);
    close(server_to_client_pipe[0]);

    // <<< 关键改动：在堆上创建一块连续的、受我们控制的内存区域
    char *memory_block = malloc(256);
    if (!memory_block) exit(1);

    // 在这块内存的开头，放置一个模拟的、只有1字节的"真实"payload
    char *actual_payload_location = memory_block;
    *actual_payload_location = 'A';

    // 紧挨着这个payload，我们放入服务器的敏感数据
    strcpy(memory_block + 1, "SESSION_ID=deadbeef;ADMIN_TOKEN=424242;");
    
    // --- 漏洞利用流程开始 ---

    unsigned char request_header[3]; // 只读取请求头（类型+长度）
    // 1. === 系统调用: read ===
    // 从管道中只读取3个字节的头部信息
    ssize_t bytes_read = read(client_to_server_pipe[0], request_header, sizeof(request_header));
    if (bytes_read <= 0) {
        free(memory_block);
        exit(1);
    }
    
    // 解析心跳请求头
    unsigned char* p = request_header;
    unsigned char type = *p++;
    unsigned int declared_payload_len; // 客户端声明的长度
    n2s(p, declared_payload_len);

    if (type == HEARTBEAT_REQUEST) {
        printf("[服务器] 收到心跳请求，声明的Payload长度: %u\n", declared_payload_len);
        
        // 2. === 系统调用: mmap (由malloc触发) ===
        unsigned char* response_buffer = malloc(3 + declared_payload_len);
        if (!response_buffer) {
            free(memory_block);
            exit(1);
        }
        printf("[服务器] 根据声明的长度分配了 %u 字节的响应内存。\n", 3 + declared_payload_len);
        
        // 填充响应头
        unsigned char* bp = response_buffer;
        *bp++ = HEARTBEAT_RESPONSE;
        s2n(declared_payload_len, bp);
        bp += 2;

        // *** 用户空间漏洞：memcpy越界读取 ***
        // <<< 关键改动：现在memcpy的源地址是我们精确控制的 memory_block
        // 它会从 'A' 开始，越界读取我们紧接着存放的秘密数据
        memcpy(bp, actual_payload_location, declared_payload_len);

        // 3. === 系统调用: write ===
        printf("[服务器] 正在将 %u 字节的响应写回管道...\n", (unsigned int)(3 + declared_payload_len));
        write(server_to_client_pipe[1], response_buffer, 3 + declared_payload_len);

        free(response_buffer);
    }

    // 清理
    free(memory_block);
    close(client_to_server_pipe[0]);
    close(server_to_client_pipe[1]);
}

// 模拟的恶意客户端进程
void malicious_client_process() {
    close(client_to_server_pipe[0]);
    close(server_to_client_pipe[1]);

    // 恶意请求现在只包含头部。我们想泄露64字节。
    unsigned char request_header[3];
    request_header[0] = HEARTBEAT_REQUEST;
    s2n(64, &request_header[1]); 

    // === 系统调用: write ===
    // 只将请求头写入管道
    printf("[客户端] 发送恶意请求头 (大小: 3字节, 声明payload: 64字节)\n");
    write(client_to_server_pipe[1], request_header, sizeof(request_header));
    
    // === 系统调用: read ===
    char response_buffer[1024] = {0};
    read(server_to_client_pipe[0], response_buffer, sizeof(response_buffer));

    printf("\n==================== 客户端收到泄露的数据 ====================\n");
    // 为了可读性，打印泄露的字符串部分（跳过3字节响应头）
    printf("%s\n", response_buffer + 3);
    printf("==============================================================\n");
    
    close(client_to_server_pipe[1]);
    close(server_to_client_pipe[0]);
}

int main() {
    if (pipe(client_to_server_pipe) == -1 || pipe(server_to_client_pipe) == -1) {
        perror("pipe");
        exit(1);
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) {
        vulnerable_server_process();
    } else {
        malicious_client_process();
        wait(NULL);
    }

    return 0;
}