#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "tcp_ao.h"
#include "tcp_ao_config.h"
#include <errno.h>
#include "server_client_comm.h"


#define SERVER_IP "127.0.0.1"

// Function to test setting TCP-AO
void test_set_tcpA0_sockopt() {
    printf("Starting test_set_tcpA0_sockopt\n");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0){
		printf("Error creating the socket, errno: %d, %s\n", errno, strerror(errno));
		return;
	} else {
		printf("Socket created successfully\n");
	}

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);


    uint8_t sndid = 100, rcvid = 100;

    int result = set_tcpA0_sockopt(sock, AF_INET, ALGORITHM, sndid, KEY, rcvid);
    printf("result: %d\n", result);
    assert(result == 0); // Assert the setsockopt call was successful

    printf("Coneccting to the server\n");
    result = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if(result != 0){
        perror("Connect failed");
    }
    printf("Connected to the server\n");



    const char *message = "Hello, World!";
    
    printf("Sending message to the server\n");
    send(sock, message, strlen(message), 0);
    printf("Message sent to the server\n");


    close(sock);

    printf("test_set_tcpA0_sockopt passed.\n");
}

int main() {
    test_set_tcpA0_sockopt();
    return 0;
}
