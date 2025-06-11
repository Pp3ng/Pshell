#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>   // signal handling
#include <termios.h>  // terminal control
#include <limits.h>   // PATH_MAX definition
#include <pwd.h>      // user information
#include <time.h>     // time functions
#include <sys/time.h> // gettimeofday
#include <errno.h>    // error handling
#include <glob.h>     // wildcard expansion(* and ?)
#include <ctype.h>    // for isspace
#include <stdbool.h>  // for bool type

#ifndef GLOB_TILDE
#define GLOB_TILDE 0
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// shell configuration constants
#define MAX_LINE 2048           //  maximum command line length
#define MAX_ARGS 128            //  maximum number of arguments
#define HISTORY_SIZE 1000       //  maximum history size
#define MAX_PIPELINE 10         // maximum commands in pipeline
#define PROMPT_BUFFER_SIZE 4096 // buffer size for prompt

// ANSI color codes for better readability
#define COLOR_RED "\033[1;31m"
#define COLOR_GREEN "\033[1;32m"
#define COLOR_YELLOW "\033[1;33m"
#define COLOR_BLUE "\033[1;34m"
#define COLOR_CYAN "\033[1;36m"
#define COLOR_RESET "\033[0m"

#define HANDLE_ERROR(msg)   \
    do                      \
    {                       \
        perror(msg);        \
        exit(EXIT_FAILURE); \
    } while (0) // error handling macro

void log_error(const char *msg, int should_perror)
{
    fprintf(stderr, "%sError: %s%s\n", COLOR_RED, msg, COLOR_RESET);
    if (should_perror)
    {
        perror("System error");
    }
}

char *safe_strdup(const char *str)
{
    if (!str)
        return NULL;
    char *newstr = strdup(str);
    if (!newstr)
    {
        fprintf(stderr, "%sFailed to allocate memory%s\n", COLOR_RED, COLOR_RESET);
        exit(EXIT_FAILURE);
    }
    return newstr;
}

void safe_strncpy(char *dest, const char *src, size_t size)
{
    if (!dest || !src || size == 0)
        return;

    strncpy(dest, src, size - 1);
    dest[size - 1] = '\0';
}

// Trim leading and trailing whitespace
char *trim_whitespace(char *str)
{
    if (!str)
        return NULL;

    // Trim leading space
    while (isspace((unsigned char)*str))
        str++;

    if (*str == 0) // All spaces?
        return str;

    // Trim trailing space
    char *end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end))
        end--;

    end[1] = '\0';
    return str;
}

// Validates if the string is NULL or contains only whitespace characters
bool is_empty_or_whitespace(const char *str)
{
    if (!str)
        return true;

    while (*str)
    {
        if (!isspace((unsigned char)*str))
            return false;
        str++;
    }
    return true;
}

// command execution status
typedef enum
{
    SUCCESS = 0,
    ERROR = -1
} ExecutionStatus;

// command type enumeration
typedef enum
{
    CMD_NORMAL,
    CMD_BUILTIN,
    CMD_PIPELINE,
    CMD_BACKGROUND
} CommandType;

typedef struct
{
    char *args[MAX_ARGS]; // Command arguments
    int arg_count;        // Number of arguments
    char *infile;         // Input redirection file
    char *outfile;        // Output redirection file
    char *appendfile;     // Append redirection file
    int background;       // Whether to run in background
    CommandType type;     // Type of command
} Command;

// shell state structure
typedef struct
{
    char *history[HISTORY_SIZE];
    int history_count;
    double last_exec_time;
    int exit_flag;
    char *previous_directory;
} ShellState;

// global shell state
ShellState shell_state = {
    .history = {NULL},
    .history_count = 0,
    .last_exec_time = 0.0,
    .exit_flag = 0,
    .previous_directory = NULL,
};

// forward declarations of key functions
void execute_command(char *command);
void execute_pipeline(char *command);
ExecutionStatus handle_builtin(char **args);
void handle_signal(int sig);

// signal handler implementation
void handle_signal(int sig)
{
    if (sig == SIGINT)
    {
        printf("\n%sInterrupted! Type 'exit' to quit.%s 😮\n", COLOR_YELLOW, COLOR_RESET);
        fflush(stdout); // flush output buffer
    }
}

// welcome message
void print_welcome_message(void)
{
    printf("%s", COLOR_CYAN);
    printf("╔════════════════════════════════╗\n");
    printf("║      Welcome to PShell!        ║\n");
    printf("║      Edition:2025.06.11(2.3)   ║\n");
    printf("║   Type 'help' for commands     ║\n");
    printf("╚════════════════════════════════╝\n");
    printf("%s", COLOR_RESET);
}

// show help message
void show_help(void)
{
    printf("%sBuilt-in Commands:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  cd [dir]      - Change directory\n");
    printf("  pwd           - Print working directory\n");
    printf("  history       - Show command history\n");
    printf("  exit          - Exit shell\n\n");

    printf("%sFeatures:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  • Pipeline: cmd1 | cmd2 | cmd3\n");
    printf("  • Redirection: >, >>, <\n");
    printf("  • Background: command &\n");
    printf("  • Environment variables: $VAR\n");
    printf("  • Command history persistence\n");
}

// job states
typedef enum
{
    JOB_RUNNING, // currently running
    JOB_STOPPED, // stopped by signal
    JOB_DONE     // completed
} JobState;

// job structure
typedef struct job
{
    pid_t pid;        // process ID
    int job_id;       // job ID
    JobState state;   // current state
    char *command;    // command string
    struct job *next; // next job in list
} Job;

// global job list
Job *job_list = NULL;
int next_job_id = 1;

// get job by pid
Job *get_job_by_pid(pid_t pid)
{
    for (Job *job = job_list; job != NULL; job = job->next)
    {
        if (job->pid == pid)
        {
            return job;
        }
    }
    return NULL;
}

// get job by job id
Job *get_job_by_jid(int jid)
{
    for (Job *job = job_list; job != NULL; job = job->next)
    {
        if (job->job_id == jid)
        {
            return job;
        }
    }
    return NULL;
}

// add new job to list
Job *add_job(pid_t pid, JobState state, const char *command)
{
    Job *job = malloc(sizeof(Job));
    if (!job)
        return NULL;

    job->pid = pid;
    job->job_id = next_job_id++;
    job->state = state;
    job->command = strdup(command);
    job->next = job_list;
    job_list = job;

    return job;
}

// remove job from list
void remove_job(Job *job)
{
    if (!job)
        return;
    for (Job **curr = &job_list; *curr; curr = &(*curr)->next)
    {
        if (*curr == job)
        {
            *curr = job->next;
            free(job->command);
            free(job);
            break;
        }
    }
}

// update job state
void update_job_state(pid_t pid, JobState state)
{
    Job *job = get_job_by_pid(pid);
    if (job)
    {
        job->state = state;
    }
}

// list all jobs
void list_jobs(void)
{
    Job *job = job_list;
    while (job != NULL)
    {
        const char *state_str = "";
        switch (job->state)
        {
        case JOB_RUNNING:
            state_str = "Running";
            break;
        case JOB_STOPPED:
            state_str = "Stopped";
            break;
        case JOB_DONE:
            state_str = "Done";
            break;
        }
        printf("[%d] %s\tPID: %d\t%s\n",
               job->job_id, state_str, job->pid, job->command);
        job = job->next;
    }
}

// job control signal handlers
void sigchld_handler(int sig)
{
    (void)sig; // suppress unused parameter warning

    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0)
    {
        if (WIFEXITED(status))
        {
            update_job_state(pid, JOB_DONE);
        }
        else if (WIFSTOPPED(status))
        {
            update_job_state(pid, JOB_STOPPED);
            Job *job = get_job_by_pid(pid);
            if (job)
            {
                printf("\n[%d] Stopped\t%s\n", job->job_id, job->command);
            }
        }
        else if (WIFCONTINUED(status))
        {
            update_job_state(pid, JOB_RUNNING);
        }
    }
}

// initialize job control
void init_job_control(void)
{
    // put shell in its own process group
    pid_t shell_pgid = getpid();
    if (setpgid(shell_pgid, shell_pgid) < 0)
    {
        perror("setpgid failed");
        exit(EXIT_FAILURE);
    }

    // take control of terminal
    tcsetpgrp(STDIN_FILENO, shell_pgid);

    // ignore interactive and job-control signals
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGCHLD, sigchld_handler);
}

// handle fg command
ExecutionStatus handle_fg(char **args)
{
    if (!args[1] || is_empty_or_whitespace(args[1]))
    {
        fprintf(stderr, "fg: job id required\n");
        return ERROR;
    }

    int jid = atoi(trim_whitespace(args[1]));
    Job *job = get_job_by_jid(jid);
    if (!job)
    {
        fprintf(stderr, "fg: job %d not found\n", jid);
        return ERROR;
    }

    // continue process
    if (kill(-job->pid, SIGCONT) < 0)
    {
        perror("kill (SIGCONT)");
        return ERROR;
    }

    // wait for it to finish or stop
    int status;
    if (waitpid(job->pid, &status, WUNTRACED) < 0)
    {
        perror("waitpid");
        return ERROR;
    }

    return SUCCESS;
}

// handle bg command
ExecutionStatus handle_bg(char **args)
{
    if (!args[1] || is_empty_or_whitespace(args[1]))
    {
        fprintf(stderr, "bg: job id required\n");
        return ERROR;
    }

    int jid = atoi(trim_whitespace(args[1]));
    Job *job = get_job_by_jid(jid);
    if (!job)
    {
        fprintf(stderr, "bg: job %d not found\n", jid);
        return ERROR;
    }

    if (kill(-job->pid, SIGCONT) < 0)
    {
        perror("kill (SIGCONT)");
        return ERROR;
    }

    job->state = JOB_RUNNING;
    printf("[%d] %s &\n", job->job_id, job->command);

    return SUCCESS;
}

// handle jobs command
ExecutionStatus handle_jobs(void)
{
    list_jobs();
    return SUCCESS;
}

// history management functions
void add_to_history(const char *command)
{
    if (is_empty_or_whitespace(command))
        return;

    if (shell_state.history_count >= HISTORY_SIZE)
    {
        free(shell_state.history[0]);
        memmove(shell_state.history, shell_state.history + 1,
                (HISTORY_SIZE - 1) * sizeof(char *));
        shell_state.history_count--;
    }

    shell_state.history[shell_state.history_count++] = strdup(command);
}

// environment variable replacement
void replace_env_vars(char *command)
{
    static char buffer[MAX_LINE];
    char *start = command;
    char *dollar, *end, *env_var, *env_value;

    while ((dollar = strchr(start, '$')) != NULL)
    {
        end = strpbrk(dollar + 1, " \t\n\"'");
        if (!end)
            end = dollar + strlen(dollar);

        env_var = strndup(dollar + 1, end - dollar - 1);
        env_value = getenv(env_var);

        if (env_value)
        {
            size_t prefix_len = dollar - command;
            size_t suffix_len = strlen(end);
            size_t env_len = strlen(env_value);

            if (prefix_len + env_len + suffix_len >= MAX_LINE)
            {
                fprintf(stderr, "%sEnvironment variable expansion too long%s\n",
                        COLOR_RED, COLOR_RESET);
                free(env_var);
                return;
            }

            strncpy(buffer, command, prefix_len);
            strcpy(buffer + prefix_len, env_value);
            strcpy(buffer + prefix_len + env_len, end);
            strcpy(command, buffer);
            start = command + prefix_len + env_len;
        }
        else
        {
            start = end;
        }
        free(env_var);
    }
}

ExecutionStatus execute_single_command(Command *cmd)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        log_error("Failed to fork process", 1);
        return ERROR;
    }

    if (pid == 0)
    { // child process
        // put process in its own process group
        if (setpgid(0, 0) < 0)
        {
            HANDLE_ERROR("setpgid");
        }

        if (!cmd->background)
        {
            // give terminal control to child process
            if (tcsetpgrp(STDIN_FILENO, getpid()) < 0)
            {
                HANDLE_ERROR("tcsetpgrp");
            }
        }

        // reset signal handlers for child process
        signal(SIGINT, SIG_DFL);
        signal(SIGQUIT, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGTTIN, SIG_DFL);
        signal(SIGTTOU, SIG_DFL);
        signal(SIGCHLD, SIG_DFL);

        // for background process, redirect standard output to /dev/null if not already redirected
        if (cmd->background && !cmd->outfile && !cmd->appendfile)
        {
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull < 0)
            {
                HANDLE_ERROR("open /dev/null");
            }
            if (dup2(devnull, STDOUT_FILENO) < 0)
            {
                HANDLE_ERROR("dup2 stdout");
            }
            if (dup2(devnull, STDERR_FILENO) < 0)
            {
                HANDLE_ERROR("dup2 stderr");
            }
            close(devnull);
        }

        // handle input redirection
        if (cmd->infile)
        {
            int fd = open(cmd->infile, O_RDONLY);
            if (fd < 0)
            {
                HANDLE_ERROR("Input redirection failed");
            }
            if (dup2(fd, STDIN_FILENO) < 0)
            {
                HANDLE_ERROR("dup2");
            }
            close(fd);
        }

        // handle output redirection
        if (cmd->outfile)
        {
            int fd = open(cmd->outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0)
            {
                HANDLE_ERROR("Output redirection failed");
            }
            if (dup2(fd, STDOUT_FILENO) < 0)
            {
                HANDLE_ERROR("dup2");
            }
            close(fd);
        }

        // handle append redirection
        if (cmd->appendfile)
        {
            int fd = open(cmd->appendfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd < 0)
            {
                HANDLE_ERROR("Append redirection failed");
            }
            if (dup2(fd, STDOUT_FILENO) < 0)
            {
                HANDLE_ERROR("dup2");
            }
            close(fd);
        }

        // execute command
        execvp(cmd->args[0], cmd->args);
        fprintf(stderr, "%sCommand not found: %s (%s)%s\n",
                COLOR_RED, cmd->args[0], strerror(errno), COLOR_RESET);
        exit(EXIT_FAILURE);
    }

    // parent process
    // ensure child is in its own process group
    if (setpgid(pid, pid) < 0)
    {
        // ignore EACCES error which can happen if child has already executed
        if (errno != EACCES)
        {
            HANDLE_ERROR("setpgid");
        }
    }

    // create command string for job list
    char cmd_str[MAX_LINE] = "";
    size_t pos = 0;
    size_t remaining = MAX_LINE;

    for (int i = 0; cmd->args[i] != NULL; i++)
    {
        size_t arg_len = strlen(cmd->args[i]);
        size_t required = arg_len + 1; // arg + space

        if (remaining > required)
        {
            pos += snprintf(cmd_str + pos, remaining, "%s ", cmd->args[i]);
            remaining = MAX_LINE - pos;
        }
        else
        {
            break; // Prevent buffer overflow
        }
    }

    if (!cmd->background)
    {
        // give terminal control to child process group
        if (tcsetpgrp(STDIN_FILENO, pid) < 0)
        {
            HANDLE_ERROR("tcsetpgrp");
        }

        // wait for foreground process
        int status;
        pid_t wait_pid = waitpid(pid, &status, WUNTRACED);

        // take back terminal control
        if (tcsetpgrp(STDIN_FILENO, getpid()) < 0)
        {
            HANDLE_ERROR("tcsetpgrp");
        }

        if (wait_pid == -1)
        {
            // Check if no child exists before showing error
            if (errno != ECHILD)
            {
                HANDLE_ERROR("waitpid");
            }
        }

        if (WIFSTOPPED(status))
        {
            // process was stopped (Ctrl+Z), add to job list
            add_job(pid, JOB_STOPPED, cmd_str);
            printf("\n[%d] Stopped\t%s\n", next_job_id - 1, cmd_str);
            return SUCCESS;
        }

        return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? SUCCESS : ERROR;
    }
    else
    {
        // add background process to job list
        add_job(pid, JOB_RUNNING, cmd_str);
        printf("[%d] %d\t%s &\n", next_job_id - 1, pid, cmd_str);
        return SUCCESS;
    }
}

void parse_command(char *cmd_str, Command *cmd)
{
    char *token;

    // Initialize command structure
    cmd->arg_count = 0;
    cmd->infile = cmd->outfile = cmd->appendfile = NULL;
    cmd->background = 0;
    cmd->type = CMD_NORMAL;

    token = strtok(cmd_str, " \t\n");
    while (token && cmd->arg_count < MAX_ARGS - 1)
    {
        if (strcmp(token, "<") == 0)
        {
            token = strtok(NULL, " \t\n");
            cmd->infile = token;
        }
        else if (strcmp(token, ">") == 0)
        {
            token = strtok(NULL, " \t\n");
            cmd->outfile = token;
        }
        else if (strcmp(token, ">>") == 0)
        {
            token = strtok(NULL, " \t\n");
            cmd->appendfile = token;
        }
        else if (strcmp(token, "&") == 0)
        {
            cmd->background = 1;
            cmd->type = CMD_BACKGROUND;
        }
        else
        {
            glob_t glob_result; // for wildcard expansion
            int glob_ret = glob(token, GLOB_NOCHECK | GLOB_TILDE, NULL, &glob_result);

            if (glob_ret == 0)
            {
                for (size_t i = 0; i < glob_result.gl_pathc && cmd->arg_count < MAX_ARGS - 1; i++)
                {
                    cmd->args[(cmd->arg_count)++] = safe_strdup(glob_result.gl_pathv[i]);
                }
                globfree(&glob_result);
            }
            else
            {
                cmd->args[(cmd->arg_count)++] = safe_strdup(token);
            }
        }
        token = strtok(NULL, " \t\n");
    }
    cmd->args[cmd->arg_count] = NULL;
}

void execute_pipeline(char *cmd_str)
{
    char *commands[MAX_PIPELINE];
    int cmd_count = 0;
    char *token;

    // Split the command string by pipes
    token = strtok(cmd_str, "|");
    while (token && cmd_count < MAX_PIPELINE)
    {
        char *trimmed_cmd = trim_whitespace(token);
        if (!is_empty_or_whitespace(trimmed_cmd))
        {
            commands[cmd_count++] = trimmed_cmd;
        }
        token = strtok(NULL, "|");
    }

    // Create pipes for communication
    int pipes[MAX_PIPELINE - 1][2];
    for (int i = 0; i < cmd_count - 1; i++)
    {
        if (pipe(pipes[i]) < 0)
        {
            log_error("Failed to create pipe", 1);
            return;
        }
    }

    // Fork and execute each command in the pipeline
    for (int i = 0; i < cmd_count; i++)
    {
        pid_t pid = fork();
        if (pid == 0) // Child process
        {
            // Configure pipe input
            if (i > 0)
            {
                if (dup2(pipes[i - 1][0], STDIN_FILENO) < 0)
                {
                    HANDLE_ERROR("dup2 for pipe input");
                }
            }

            // Configure pipe output
            if (i < cmd_count - 1)
            {
                if (dup2(pipes[i][1], STDOUT_FILENO) < 0)
                {
                    HANDLE_ERROR("dup2 for pipe output");
                }
            }

            // Close all pipe file descriptors
            for (int j = 0; j < cmd_count - 1; j++)
            {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }

            // Parse and execute command
            Command cmd = {0}; // Initialize with zeros
            parse_command(commands[i], &cmd);

            // Handle builtin commands
            if (handle_builtin(cmd.args) == SUCCESS)
            {
                exit(EXIT_SUCCESS);
            }

            // Execute external command
            if (execvp(cmd.args[0], cmd.args) < 0)
            {
                fprintf(stderr, "%sPipeline command failed: %s (%s)%s\n",
                        COLOR_RED, cmd.args[0], strerror(errno), COLOR_RESET);
                exit(EXIT_FAILURE);
            }
        }
        else if (pid < 0)
        {
            log_error("Failed to fork process for pipeline", 1);
            return;
        }
    }

    // Close all pipe file descriptors in parent
    for (int i = 0; i < cmd_count - 1; i++)
    {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    // Wait for all child processes to finish
    for (int i = 0; i < cmd_count; i++)
        wait(NULL);
}

// prompt generation
char *get_prompt(void)
{
    static char prompt[PROMPT_BUFFER_SIZE];
    char hostname[256];
    char cwd[PATH_MAX];
    struct passwd *pw = getpwuid(getuid());

    // get hostname
    if (gethostname(hostname, sizeof(hostname)) < 0)
    {
        safe_strncpy(hostname, "unknown", sizeof(hostname));
    }

    // get current working directory
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        safe_strncpy(cwd, "???", sizeof(cwd));
    }

    int written = snprintf(prompt, PROMPT_BUFFER_SIZE,
                           "%s%s@%s%s:%s%s%s$ %s[%.2fs]%s",
                           COLOR_GREEN, pw->pw_name, hostname, COLOR_RESET,
                           COLOR_BLUE, cwd, COLOR_RESET,
                           COLOR_RED, shell_state.last_exec_time, COLOR_RESET);

    if (written >= PROMPT_BUFFER_SIZE)
    {
        snprintf(prompt + PROMPT_BUFFER_SIZE - 4, 4, "...");
    }

    return prompt;
}

// file operations for persistence
void save_shell_state(void)
{
    // save history
    FILE *hist_file = fopen(".ps_history", "w");
    if (hist_file)
    {
        for (int i = 0; i < shell_state.history_count; i++)
        {
            if (shell_state.history[i] && !is_empty_or_whitespace(shell_state.history[i]))
            {
                // Remove existing newline if present, then add a single newline
                char *history_entry = shell_state.history[i];
                size_t len = strlen(history_entry);
                if (len > 0 && history_entry[len - 1] == '\n')
                {
                    fprintf(hist_file, "%.*s\n", (int)(len - 1), history_entry);
                }
                else
                {
                    fprintf(hist_file, "%s\n", history_entry);
                }
            }
        }
        fclose(hist_file);
    }
    else
    {
        log_error("Could not open history file for writing", 1);
    }
}

void load_shell_state(void)
{
    // load history
    FILE *hist_file = fopen(".ps_history", "r");
    if (hist_file)
    {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), hist_file))
        {
            char *trimmed_line = trim_whitespace(line);
            if (!is_empty_or_whitespace(trimmed_line))
            {
                add_to_history(trimmed_line);
            }
        }
        fclose(hist_file);
    }
}

// builtin command handling
ExecutionStatus handle_builtin(char **args)
{
    if (!args[0])
        return ERROR;

    // cd command
    if (strcmp(args[0], "cd") == 0)
    {
        char current_dir[PATH_MAX];
        if (getcwd(current_dir, sizeof(current_dir)) == NULL)
        {
            perror("getcwd");
            return ERROR;
        }

        const char *target_dir = NULL;
        char *arg_path = args[1] ? trim_whitespace(args[1]) : NULL;

        // no argument or ~ - go to home directory
        if (!arg_path || is_empty_or_whitespace(arg_path) || (arg_path[0] == '~' && arg_path[1] == '\0'))
        {
            target_dir = getenv("HOME");
            if (!target_dir)
            {
                fprintf(stderr, "cd: HOME not set\n");
                return ERROR;
            }
        }
        // handle cd -
        else if (strcmp(arg_path, "-") == 0)
        {
            if (!shell_state.previous_directory)
            {
                fprintf(stderr, "cd: OLDPWD not set\n");
                return ERROR;
            }
            target_dir = shell_state.previous_directory;
            printf("%s\n", target_dir); // print directory when using cd -
        }
        // handle ~ at start of path
        else if (arg_path[0] == '~' && arg_path[1] == '/')
        {
            const char *home = getenv("HOME");
            if (!home)
            {
                fprintf(stderr, "cd: HOME not set\n");
                return ERROR;
            }
            static char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s%s", home, arg_path + 1);
            target_dir = full_path;
        }
        // normal directory
        else
        {
            target_dir = arg_path;
        }

        if (chdir(target_dir) != 0)
        {
            perror("cd");
            return ERROR;
        }

        // update previous directory
        free(shell_state.previous_directory);
        shell_state.previous_directory = strdup(current_dir);

        return SUCCESS;
    }

    // pwd command
    if (strcmp(args[0], "pwd") == 0)
    {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)))
        {
            printf("%s\n", cwd);
            return SUCCESS;
        }
        perror("pwd");
        return ERROR;
    }

    // history command
    if (strcmp(args[0], "history") == 0)
    {
        for (int i = 0; i < shell_state.history_count; i++)
        {
            char *history_entry = shell_state.history[i];
            // remove newline character
            size_t len = strlen(history_entry);
            if (len > 0 && history_entry[len - 1] == '\n')
            {
                history_entry[len - 1] = '\0'; // remove last character
            }

            dprintf(STDOUT_FILENO, "%s%3d%s %s\n",
                    COLOR_YELLOW, i + 1, COLOR_RESET,
                    history_entry);
        }
        return SUCCESS;
    }

    // jobs command

    if (strcmp(args[0], "jobs") == 0)
    {
        return handle_jobs();
    }

    if (strcmp(args[0], "fg") == 0)
    {
        return handle_fg(args);
    }

    if (strcmp(args[0], "bg") == 0)
    {
        return handle_bg(args);
    }

    // help command
    if (strcmp(args[0], "help") == 0)
    {
        show_help();
        return SUCCESS;
    }

    // exit command
    if (strcmp(args[0], "exit") == 0)
    {
        printf("Goodbye! 😊\n");
        shell_state.exit_flag = 1;
        return SUCCESS;
    }

    return ERROR; // not a builtin command
}

char *preprocess_command(const char *orig_cmd)
{
    char *processed_cmd = strdup(orig_cmd);
    if (!processed_cmd)
        return NULL;

    // Handle environment variables
    replace_env_vars(processed_cmd);

    return processed_cmd;
}

void execute_command(char *cmd_str)
{
    struct timeval start, end;
    Command cmd = {0}; // Initialize command structure

    // Start timing
    gettimeofday(&start, NULL);

    // Preprocess command (handle environment variables)
    char *processed_cmd = preprocess_command(cmd_str);
    if (!processed_cmd)
    {
        log_error("Failed to preprocess command", 0);
        return;
    }

    // Parse command into structured form
    parse_command(processed_cmd, &cmd);

    if (cmd.arg_count > 0)
    {
        // Try built-in commands first
        if (handle_builtin(cmd.args) == ERROR)
        {
            // Not a built-in, execute as external command
            execute_single_command(&cmd);
        }
    }

    // Cleanup allocated memory
    for (int i = 0; i < cmd.arg_count; i++)
    {
        free(cmd.args[i]);
    }
    free(processed_cmd);

    // End timing and update execution time
    gettimeofday(&end, NULL);
    shell_state.last_exec_time =
        (end.tv_sec - start.tv_sec) +
        (end.tv_usec - start.tv_usec) / 1e6;
}

void initialize_shell(void)
{
    print_welcome_message();
    signal(SIGINT, handle_signal);
    load_shell_state();
    init_job_control();
}

void cleanup_shell(void)
{
    save_shell_state();

    // Free allocated memory
    for (int i = 0; i < shell_state.history_count; i++)
    {
        free(shell_state.history[i]);
    }
    free(shell_state.previous_directory);
}

void process_command_line(char *cmd_str)
{
    // Trim whitespace and check if command is empty
    char *trimmed = trim_whitespace(cmd_str);
    if (is_empty_or_whitespace(trimmed))
        return;

    // Add to history
    add_to_history(cmd_str);

    // Check for pipeline
    if (strchr(cmd_str, '|'))
    {
        struct timeval start, end;
        gettimeofday(&start, NULL);

        execute_pipeline(cmd_str);

        gettimeofday(&end, NULL);
        shell_state.last_exec_time =
            (end.tv_sec - start.tv_sec) +
            (end.tv_usec - start.tv_usec) / 1e6;
    }
    else
    {
        execute_command(cmd_str);
    }
}

int main(void)
{
    char command[MAX_LINE];

    // Initialize shell environment
    initialize_shell();

    // Main shell loop
    while (!shell_state.exit_flag)
    {
        // Display prompt
        char *prompt = get_prompt();
        printf("%s", prompt);
        fflush(stdout); // Ensure immediate output

        // Read command
        if (!fgets(command, MAX_LINE, stdin))
        {
            if (feof(stdin))
            {
                printf("\nLogout\n");
                break;
            }
            perror("fgets");
            continue;
        }

        // Process the command
        process_command_line(command);
    }

    // Clean up before exit
    cleanup_shell();

    return EXIT_SUCCESS;
}
