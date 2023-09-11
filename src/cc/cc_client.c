#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_CMD_SIZE 1024

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

    // Parse host and port from command line argument
    if (sscanf(argv[1], "%1023[^:]:%5s", host, port) != 2) {
        fprintf(stderr, "Invalid format. Use: host:port\n");
        return EXIT_FAILURE;
    }

    // Set hints for getaddrinfo
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; // Allow IPv4 or IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the host name/IP
    if (getaddrinfo(host, port, &hints, &result) != 0) {
        perror("getaddrinfo");
        return EXIT_FAILURE;
    }

    // Create a socket
    if ((sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) < 0) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }

    // Try each address until we successfully connect
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
            break; // Success
        }
    }

    if (rp == NULL) {
        fprintf(stderr, "Could not connect\n");
        return EXIT_FAILURE;
    }

    freeaddrinfo(result); // No longer needed

    while (1) {
        printf("Enter command: ");
        fgets(buffer, MAX_CMD_SIZE, stdin);
        buffer[strcspn(buffer, "\n")] = 0;  // Remove trailing newline

        // Check for empty or invalid command
        if (strlen(buffer) == 0) {
            continue;
        }

        // Send the command to the server
        if (send(sock, buffer, strlen(buffer), 0) < 0) {
            perror("Send failed");
            break;
        }

        // Receive the output from the server
        memset(buffer, 0, MAX_CMD_SIZE);
        ssize_t bytesRead = recv(sock, buffer, MAX_CMD_SIZE, 0);
        if (bytesRead <= 0) {
            perror("Server disconnected or read error");
            break;
        }
        buffer[bytesRead] = '\0';  // Null-terminate the string
        printf("Received output:\n%s\n", buffer);
    }

    close(sock);

    return EXIT_SUCCESS;
}
