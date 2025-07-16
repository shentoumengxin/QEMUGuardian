#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};
    char large_data[8192]; // 8KB of data

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        return 1;
    }
    
    printf("Connected to listener. Please type a short message in the netcat terminal and press Enter.\n");
    
    int bytes_received = recv(sock, buffer, 1024, 0);
    printf("Received %d bytes: %s\n", bytes_received, buffer);

    memset(large_data, 'A', sizeof(large_data));
    printf("Sending large amount of data...\n");
    send(sock, large_data, sizeof(large_data), 0);
    printf("Data sent.\n");
    
    close(sock);
    return 0;
}