#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_CMD_SIZE 1024

void handle_exit(int sock) {
    close(sock);
    printf("\nConnection closed. Exiting...\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    int sock = 0;
    char buffer[MAX_CMD_SIZE] = {0};
    char host[1024];
    char port[6];
    struct addrinfo hints, *result, *rp;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <host:port>\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (sscanf(argv[1], "%1023[^:]:%5s", host, port) != 2) {
        fprintf(stderr, "Invalid format. Use: host:port\n");
        return EXIT_FAILURE;
    }

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &result) != 0) {
        perror("getaddrinfo");
        return EXIT_FAILURE;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) break;
        close(sock);
    }

    if (rp == NULL) {
        fprintf(stderr, "Could not connect\n");
        return EXIT_FAILURE;
    }

    freeaddrinfo(result);

    signal(SIGINT, handle_exit);  // Handle Ctrl+C gracefully

while (1) {
    printf("Enter command: ");
    if (fgets(buffer, MAX_CMD_SIZE, stdin) == NULL) {
        perror("fgets");
        continue;
    }

    buffer[strcspn(buffer, "\n")] = 0;

    if (strlen(buffer) == 0) {
        continue;
    }

    if (send(sock, buffer, strlen(buffer), 0) < 0) {
        perror("Send failed");
        close(sock);
        
        // Reconnection logic
        while (1) {
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sock == -1) continue;
                if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) break;
                close(sock);
            }
            
            if (rp != NULL) break;  // Successfully reconnected
            sleep(5);  // Wait for 5 seconds before retrying
        }
        continue;
    }

    memset(buffer, 0, MAX_CMD_SIZE);
    ssize_t bytesRead = recv(sock, buffer, MAX_CMD_SIZE, 0);
    if (bytesRead <= 0) {
        perror("Server disconnected or read error");
        close(sock);
        
        // Reconnection logic
        while (1) {
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (sock == -1) continue;
                if (connect(sock, rp->ai_addr, rp->ai_addrlen) != -1) break;
                close(sock);
            }
            
            if (rp != NULL) break;  // Successfully reconnected
            sleep(5);  // Wait for 5 seconds before retrying
        }
        continue;
    }
    buffer[bytesRead] = '\0';
    printf("Received output:\n%s\n", buffer);
}


    close(sock);
    return EXIT_SUCCESS;
}
