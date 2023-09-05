#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ftw.h>
int main() {
    pid_t parent_pid = getpid();  // Get the parent PID before forking
    pid_t pid = fork();  // Fork the process

    if (pid == 0) {
        // This block will be executed by the child process
        printf("I am the child, my PID is %d and my parent's PID is %d\n", getpid(), getppid());
        printf("Parent PID stored before fork: %d\n", parent_pid);
        exit(0);  // Exit the child process
    } else if (pid > 0) {
        // This block will be executed by the parent process
        printf("I am the parent, my PID is %d and my child's PID is %d\n", getpid(), pid);

        // Infinite loop to keep the parent process running
        while (1) {
            sleep(1);
        }
    } else {
        // Fork failed
        perror("fork");
        exit(1);
    }

    return 0;
}