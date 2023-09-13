#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAX_CMD_SIZE 1024
#define PORT 8080
#define ERROR_MESSAGE "Command not found or failed to execute"
#define ERROR_MESSAGE_LENGTH 39

void execute_command(int socket, char *cmd) {
    int pipefd[2];
    pid_t pid;

    if (pipe(pipefd) == -1) {
        perror("pipe");
        return;
    }

    pid = fork();
    if (pid == -1) {
        perror("fork");
        return;
    }

    if (pid == 0) {  
        // CLose the read of the pipe[0]
        close(pipefd[0]);

        // Redirect output to pipe.
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);

        int ret = system(cmd);
        if (ret != 0) {
            write(pipefd[1], ERROR_MESSAGE, ERROR_MESSAGE_LENGTH);
        }

        // Close pipe
        close(pipefd[1]);
        exit(0);
    } else {  
        char buffer[1024] = {0};

        close(pipefd[1]);

        ssize_t bytesRead;
        while ((bytesRead = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytesRead] = '\0';  
            send(socket, buffer, strlen(buffer), 0);
            memset(buffer, 0, sizeof(buffer));  
        }

        close(pipefd[0]);
    }
}

int start_receiver() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[MAX_CMD_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("Setsockopt");
        return EXIT_FAILURE;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        return EXIT_FAILURE;
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen");
        return EXIT_FAILURE;
    }

    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
            perror("Accept");
            continue;
        }

        while (1) {
            ssize_t bytesRead = read(new_socket, buffer, MAX_CMD_SIZE);
            if (bytesRead <= 0) {
                perror("Client disconnected or read error");
                break;
            }
            buffer[bytesRead] = '\0';  
            if (strlen(buffer) == 0) {
                continue;
            }

            execute_command(new_socket, buffer);
        }

        close(new_socket);
    }

    return EXIT_SUCCESS;
}

int main() {
    return start_receiver();
}
