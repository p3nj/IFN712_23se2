#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 8080
#define MAX_CMD_SIZE 1024

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[MAX_CMD_SIZE] = {0};

    // Create a socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        return EXIT_FAILURE;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        return EXIT_FAILURE;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        return EXIT_FAILURE;
    }

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
