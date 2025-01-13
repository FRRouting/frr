#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <errno.h>
#include "tcp_ao_config.h"
#include "server_client_comm.h"

#define PORT 12345
#define TCP_AO_MAXKEYLEN 80


void handle_client(int client_sock) {
    char buffer[1024] = {0};
    int bytes_read = read(client_sock, buffer, sizeof(buffer));
    if (bytes_read > 0) {
        printf("Received message: %s\n", buffer);
    }
    close(client_sock);
}

int main() {
    int sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }

    uint8_t sndid = 100, rcvid = 100;

    if (set_tcpA0_sockopt(sock, AF_INET, ALGORITHM, sndid, KEY, rcvid) < 0) {
        close(sock);
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return -1;
    }

    if (listen(sock, 5) < 0) {
        perror("Listen failed");
        close(sock);
        return -1;
    }

    printf("Server listening on port %d\n", PORT);

    while (1) {
        client_sock = accept(sock, (struct sockaddr *)&client_addr, &addr_len);
        if (client_sock < 0) {
            perror("Accept failed");
            continue;
        }
        handle_client(client_sock);
    }

    close(sock);
    return 0;
}
