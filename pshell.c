#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>  //  signal
#include <termios.h> //  struct termios
#include <limits.h>  //  PATH_MAX
#include <pwd.h>     //  getpwuid
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <glob.h> //ldcard expansion

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

// shell configuration constants
#define MAX_LINE 2048           // increased for longer commands
#define MAX_ARGS 128            // increased for more complex commands
#define HISTORY_SIZE 1000       // increased history size
#define ALIAS_SIZE 200          // increased alias capacity
#define MAX_PIPELINE 10         // maximum commands in pipeline
#define PROMPT_BUFFER_SIZE 4096 // increased prompt buffer size

// ansi color codes for better readability
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

char *safe_strdup(const char *str)
{
    if (!str)
        return NULL;
    char *newstr = strdup(str);
    if (!newstr)
    {
        fprintf(stderr, "%s failed to allocate memory%s\n", COLOR_RED, COLOR_RESET);
        exit(EXIT_FAILURE);
    }
    return newstr;
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

// alias structure
typedef struct
{
    char *name;
    char *command;
} Alias;

// shell state structure
typedef struct
{
    char *history[HISTORY_SIZE];
    int history_count;
    Alias aliases[ALIAS_SIZE];
    int alias_count;
    double last_exec_time;
    int exit_flag;
} ShellState;

// global shell state
ShellState shell_state = {0};

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
        printf("\n%sInterrupted! Type 'exit' to quit.%s 😮\n", COLOR_YELLOW, COLOR_RESET); // 😁
    }
    fflush(stdout); // flush the output buffer
}

// welcome message
void print_welcome_message(void)
{
    printf("%s", COLOR_CYAN);
    printf("╔════════════════════════════════╗\n");
    printf("║      Welcome to PShell 2.1     ║\n");
    printf("║   Enhanced Edition - 2024      ║\n");
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
    printf("  alias [name=cmd] - Show/set aliases\n");
    printf("  unalias name  - Remove an alias\n");
    printf("  exit          - Exit shell\n\n");

    printf("%sFeatures:%s\n", COLOR_YELLOW, COLOR_RESET);
    printf("  • Pipeline: cmd1 | cmd2 | cmd3\n");
    printf("  • Redirection: >, >>, <\n");
    printf("  • Background: command &\n");
    printf("  • Environment variables: $VAR\n");
    printf("  • Command history persistence\n");
    printf("  • Custom aliases\n");
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
    Job *job = job_list;
    while (job != NULL)
    {
        if (job->pid == pid)
        {
            return job;
        }
        job = job->next;
    }
    return NULL;
}

// get job by job id
Job *get_job_by_jid(int jid)
{
    Job *job = job_list;
    while (job != NULL)
    {
        if (job->job_id == jid)
        {
            return job;
        }
        job = job->next;
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
    Job **curr = &job_list;
    while (*curr != NULL)
    {
        if (*curr == job)
        {
            *curr = job->next;
            free(job->command);
            free(job);
            return;
        }
        curr = &((*curr)->next);
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
void list_jobs()
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
void init_job_control()
{
    // put shell in its own process group
    pid_t shell_pgid = getpid();
    if (setpgid(shell_pgid, shell_pgid) < 0)
    {
        perror("setpgid failed");
        exit(EXIT_FAILURE);
    }

    // take control of the terminal
    tcsetpgrp(STDIN_FILENO, shell_pgid);

    // ignore interactive and job-control signals
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGCHLD, sigchld_handler);
}

// handle the fg command
int handle_fg(char **args)
{
    if (!args[1])
    {
        fprintf(stderr, "fg: job id required\n");
        return ERROR;
    }

    int jid = atoi(args[1]);
    Job *job = get_job_by_jid(jid);
    if (!job)
    {
        fprintf(stderr, "fg: job %d not found\n", jid);
        return ERROR;
    }

    // continue the process
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

// handle the bg command
int handle_bg(char **args)
{
    if (!args[1])
    {
        fprintf(stderr, "bg: job id required\n");
        return ERROR;
    }

    int jid = atoi(args[1]);
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

// handle the jobs command
int handle_jobs(char **args)
{
    list_jobs();
    return SUCCESS;
}

// history management functions
void add_to_history(const char *command)
{
    if (!command || !*command)
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

// enhanced environment variable replacement
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

// improved command execution with error handling
ExecutionStatus execute_single_command(char **args,
                                       char *infile,
                                       char *outfile,
                                       char *appendfile,
                                       int background)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        HANDLE_ERROR("fork");
    }

    if (pid == 0)
    { // child process
        // put the process in its own process group
        if (setpgid(0, 0) < 0)
        {
            HANDLE_ERROR("setpgid");
        }

        if (!background)
        {
            // give the terminal control to the child process
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

        // for background process,redirect the standard input to /dev/null if not already redirected
        if (background && !outfile && !appendfile)
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
        if (infile)
        {
            int fd = open(infile, O_RDONLY);
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
        if (outfile)
        {
            int fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
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
        if (appendfile)
        {
            int fd = open(appendfile, O_WRONLY | O_CREAT | O_APPEND, 0644);
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

        // execute the command
        execvp(args[0], args);
        fprintf(stderr, "%sCommand not found: %s (%s)%s\n",
                COLOR_RED, args[0], strerror(errno), COLOR_RESET);
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
    for (int i = 0; args[i] != NULL; i++)
    {
        strcat(cmd_str, args[i]);
        strcat(cmd_str, " ");
    }

    if (!background)
    {
        // give terminal control to the child process group
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
            HANDLE_ERROR("waitpid");
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

// parse commands (< > | >> & *)
void parse_command(char *command,
                   char **args,
                   int *arg_count,
                   char **infile,
                   char **outfile,
                   char **appendfile,
                   int *background)
{
    char *token;                             // strtok is used to split the string into tokens
    *arg_count = 0;                          // initialize the arg_count to 0
    *infile = *outfile = *appendfile = NULL; // initialize the pointers to NULL
    *background = 0;                         // initialize the background to 0

    token = strtok(command, " \t\n");
    while (token && *arg_count < MAX_ARGS - 1)
    {
        if (strcmp(token, "<") == 0)
        {
            token = strtok(NULL, " \t\n");
            *infile = token;
        }
        else if (strcmp(token, ">") == 0)
        {
            token = strtok(NULL, " \t\n");
            *outfile = token;
        }
        else if (strcmp(token, ">>") == 0)
        {
            token = strtok(NULL, " \t\n");
            *appendfile = token;
        }
        else if (strcmp(token, "&") == 0)
        {
            *background = 1;
        }
        else
        {
            glob_t glob_result; // for wildcard expansion
            int glob_ret = glob(token, GLOB_NOCHECK | GLOB_TILDE, NULL, &glob_result);

            if (0 == glob_ret) // my friend tell me this trick to avoid stupid error
            {
                for (size_t i = 0; i < glob_result.gl_pathc && *arg_count < MAX_ARGS - 1; i++)
                {
                    args[(*arg_count)++] = safe_strdup(glob_result.gl_pathv[i]);
                }
                globfree(&glob_result);
            }
            else
            {
                args[(*arg_count)++] = safe_strdup(token);
            }
        }
        token = strtok(NULL, " \t\n");
    }
    args[*arg_count] = NULL;
}

// improved pipeline execution
void execute_pipeline(char *command)
{
    char *commands[MAX_PIPELINE];
    int cmd_count = 0;
    char *token;

    token = strtok(command, "|");
    while (token && cmd_count < MAX_PIPELINE)
    {
        commands[cmd_count++] = token;
        token = strtok(NULL, "|");
    }

    int pipes[MAX_PIPELINE - 1][2];
    for (int i = 0; i < cmd_count - 1; i++)
    {
        if (pipe(pipes[i]) < 0)
        {
            perror("pipe");
            return;
        }
    }

    for (int i = 0; i < cmd_count; i++)
    {
        pid_t pid = fork();
        if (pid == 0)
        {
            // configure pipe input
            if (i > 0)
            {
                dup2(pipes[i - 1][0], STDIN_FILENO);
            }
            // configure pipe output
            if (i < cmd_count - 1)
            {
                dup2(pipes[i][1], STDOUT_FILENO);
            }

            // close all pipe fds
            for (int j = 0; j < cmd_count - 1; j++)
            {
                close(pipes[j][0]);
                close(pipes[j][1]);
            }

            // parse and execute command
            char *args[MAX_ARGS];
            int arg_count;
            char *infile, *outfile, *appendfile;
            int background;

            parse_command(commands[i], args, &arg_count,
                          &infile, &outfile, &appendfile, &background);

            // handle builtin commands
            if (handle_builtin(args) == SUCCESS)
            {
                exit(EXIT_SUCCESS);
            }
            // execute external command
            if (execvp(args[0], args) < 0)
            {
                fprintf(stderr, "%sPipeline command failed: %s%s\n",
                        COLOR_RED, args[0], COLOR_RESET);
                exit(EXIT_FAILURE);
            }
        }
        else if (pid < 0)
        {
            perror("fork");
            return;
        }
    }

    // close all pipe fds in parent
    for (int i = 0; i < cmd_count - 1; i++)
    {
        close(pipes[i][0]);
        close(pipes[i][1]);
    }

    // wait for all processes
    for (int i = 0; i < cmd_count; i++)
    {
        wait(NULL);
    }
}

// enhanced prompt generation
char *get_prompt(void)
{
    static char prompt[PROMPT_BUFFER_SIZE];
    char hostname[256];
    char cwd[PATH_MAX];
    struct passwd *pw = getpwuid(getuid());

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
            fprintf(hist_file, "%s", shell_state.history[i]);
        }
        fclose(hist_file);
    }

    // save aliases
    FILE *alias_file = fopen(".ps_aliases", "w");
    if (alias_file)
    {
        for (int i = 0; i < shell_state.alias_count; i++)
        {
            fprintf(alias_file, "%s=%s\n",
                    shell_state.aliases[i].name,
                    shell_state.aliases[i].command);
        }
        fclose(alias_file);
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
            add_to_history(line);
        }
        fclose(hist_file);
    }

    // load aliases
    FILE *alias_file = fopen(".ps_aliases", "r");
    if (alias_file)
    {
        char line[MAX_LINE];
        while (fgets(line, sizeof(line), alias_file) &&
               shell_state.alias_count < ALIAS_SIZE)
        {
            char *name = strtok(line, "=");
            char *command = strtok(NULL, "\n");
            if (name && command)
            {
                shell_state.aliases[shell_state.alias_count].name = strdup(name);
                shell_state.aliases[shell_state.alias_count].command = strdup(command);
                shell_state.alias_count++;
            }
        }
        fclose(alias_file);
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
        if (!args[1])
        {
            // change to home directory if no argument
            const char *home = getenv("HOME");
            if (home && chdir(home) != 0)
            {
                perror("cd");
                return ERROR;
            }
        }
        else if (chdir(args[1]) != 0)
        {
            perror("cd");
            return ERROR;
        }
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
                history_entry[len - 1] = '\0'; // remove the last character
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
        return handle_jobs(args);
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

    // alias command
    if (strcmp(args[0], "alias") == 0)
    {
        if (!args[1])
        {
            // show all aliases
            for (int i = 0; i < shell_state.alias_count; i++)
            {
                printf("alias %s='%s'\n",
                       shell_state.aliases[i].name,
                       shell_state.aliases[i].command);
            }
            return SUCCESS;
        }

        // add new alias
        char *eq_pos = strchr(args[1], '=');
        if (!eq_pos)
        {
            fprintf(stderr, "Usage: alias name=command\n");
            return ERROR;
        }

        *eq_pos = '\0';
        char *name = args[1];
        char *command = eq_pos + 1;

        // update existing alias or add new one
        int found = 0;
        for (int i = 0; i < shell_state.alias_count; i++)
        {
            if (strcmp(shell_state.aliases[i].name, name) == 0)
            {
                free(shell_state.aliases[i].command);
                shell_state.aliases[i].command = strdup(command);
                found = 1;
                break;
            }
        }

        if (!found && shell_state.alias_count < ALIAS_SIZE)
        {
            shell_state.aliases[shell_state.alias_count].name = strdup(name);
            shell_state.aliases[shell_state.alias_count].command = strdup(command);
            shell_state.alias_count++;
        }

        return SUCCESS;
    }

    // unalias command
    if (strcmp(args[0], "unalias") == 0)
    {
        if (!args[1])
        {
            fprintf(stderr, "Usage: unalias name\n");
            return ERROR;
        }

        for (int i = 0; i < shell_state.alias_count; i++)
        {
            if (strcmp(shell_state.aliases[i].name, args[1]) == 0)
            {
                free(shell_state.aliases[i].name);
                free(shell_state.aliases[i].command);
                memmove(&shell_state.aliases[i],
                        &shell_state.aliases[i + 1],
                        (shell_state.alias_count - i - 1) * sizeof(Alias));
                shell_state.alias_count--;
                return SUCCESS;
            }
        }

        fprintf(stderr, "Alias '%s' not found\n", args[1]);
        return ERROR;
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

// command execution with alias expansion
void execute_command(char *command)
{
    char *args[MAX_ARGS];
    int arg_count;
    char *infile, *outfile, *appendfile;
    int background;
    struct timeval start, end;

    // timing start
    gettimeofday(&start, NULL);

    // process alias
    char *alias_cmd = NULL;
    char *first_word = strtok(strdup(command), " \t\n");
    if (first_word)
    {
        for (int i = 0; i < shell_state.alias_count; i++)
        {
            if (strcmp(shell_state.aliases[i].name, first_word) == 0)
            {
                size_t new_cmd_len = strlen(shell_state.aliases[i].command) +
                                     strlen(command) + 2;
                alias_cmd = malloc(new_cmd_len);
                snprintf(alias_cmd, new_cmd_len, "%s %s",
                         shell_state.aliases[i].command,
                         command + strlen(first_word));
                command = alias_cmd;
                break;
            }
        }
        free(first_word);
    }

    // handle environment variables
    replace_env_vars(command);

    // parse the command
    parse_command(command, args, &arg_count, &infile,
                  &outfile, &appendfile, &background);

    if (arg_count > 0)
    {
        // try builtin commands first
        if (handle_builtin(args) == ERROR)
        {
            // not a builtin, execute as external command
            execute_single_command(args, infile, outfile,
                                   appendfile, background);
        }
    }

    // cleanup
    for (int i = 0; i < arg_count; i++)
    {
        free(args[i]);
    }
    free(alias_cmd);

    // timing end
    gettimeofday(&end, NULL);
    shell_state.last_exec_time =
        (end.tv_sec - start.tv_sec) +
        (end.tv_usec - start.tv_usec) / 1e6;
}

// complete main function
int main(void)
{
    char command[MAX_LINE];

    // initialize shell
    print_welcome_message();
    signal(SIGINT, handle_signal);
    load_shell_state();
    init_job_control();

    // main shell loop
    while (!shell_state.exit_flag)
    {
        char *prompt = get_prompt();
        if (prompt) // check if successful
        {
            printf("%s", prompt);
            fflush(stdout); // ensuer inmediate output
        }
        else
        {
            printf(">_"); // fallback prompt if get_prompt fails
        }

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

        if (command[0] == '\n')
            continue;

        // add to history
        add_to_history(command);

        // check for pipeline
        if (strchr(command, '|'))
        {
            struct timeval start, end;
            gettimeofday(&start, NULL);

            execute_pipeline(command);

            gettimeofday(&end, NULL);
            shell_state.last_exec_time =
                (end.tv_sec - start.tv_sec) +
                (end.tv_usec - start.tv_usec) / 1e6;
        }
        else
        {
            execute_command(command);
        }
    }

    // cleanup and save state
    save_shell_state();

    // free allocated memory
    for (int i = 0; i < shell_state.history_count; i++)
    {
        free(shell_state.history[i]);
    }
    for (int i = 0; i < shell_state.alias_count; i++)
    {
        free(shell_state.aliases[i].name);
        free(shell_state.aliases[i].command);
    }

    return EXIT_SUCCESS;
}
