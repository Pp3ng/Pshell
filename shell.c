#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>
#include <limits.h>
#include <pwd.h>

#define MAX_LINE 1024    // Maximum length of command input
#define MAX_ARGS 100     // Maximum number of arguments
#define HISTORY_SIZE 100 // Maximum number of commands in history
#define ALIAS_SIZE 100   // Maximum number of aliases

char *history[HISTORY_SIZE]; // Array to store command history
int history_count = 0;       // Number of commands in history

typedef struct
{
    char *name;
    char *command;
} Alias;

Alias aliases[ALIAS_SIZE]; // Array to store command aliases
int alias_count = 0;       // Number of aliases

void handle_signal(int sig)
{
    if (sig == SIGINT)
    {
        printf("\nCaught SIGINT. Type 'exit' to exit.😀\n");
    }
}

void print_welcome_message(void)
{
    printf("\033[1;36m"); // cyan
    printf("********************************\n");
    printf("*     Welcome to PShell         *\n");
    printf("*     Version 2.0               *\n");
    printf("*     Type 'help' for commands  *\n");
    printf("********************************\n");
    printf("\033[0m"); // reset
}

void show_help()
{
    printf("\033[1;33mShell Commands:\033[0m\n");
    printf("  cd [dir]        - Change directory\n");
    printf("  pwd            - Print working directory\n");
    printf("  ls [options]   - List directory contents\n");
    printf("  history        - Show command history\n");
    printf("  alias          - Show/set command aliases\n");
    printf("  unalias name   - Remove an alias\n");
    printf("  exit           - Exit the shell\n");
    printf("\nPipe Operations: cmd1 | cmd2\n");
    printf("Redirections: >, >>, <\n");
    printf("Background Jobs: command &\n");
    printf("Environment Variables: $VAR\n");
}

void add_to_history(char *command)
{
    if (history_count < HISTORY_SIZE)
    {
        history[history_count++] = strdup(command);
    }
    else
    {
        free(history[0]);
        memmove(history, history + 1, (HISTORY_SIZE - 1) * sizeof(char *));
        history[HISTORY_SIZE - 1] = strdup(command);
    }
}

void show_history()
{
    for (int i = 0; i < history_count; i++)
    {
        printf("%d %s", i + 1, history[i]);
    }
}

void replace_env_vars(char *command)
{
    char buffer[MAX_LINE];
    char *start = command;
    char *end;
    char *env_var;
    char *env_value;

    while ((start = strchr(start, '$')) != NULL)
    {
        end = strpbrk(start, " \n");
        if (end == NULL)
        {
            end = start + strlen(start);
        }

        env_var = strndup(start + 1, end - start - 1);
        env_value = getenv(env_var);
        free(env_var);

        if (env_value)
        {
            if (strlen(command) - (end - start) + strlen(env_value) >= MAX_LINE)
            {
                fprintf(stderr, "Environment variable value too long\n");
                return;
            }
            snprintf(buffer, sizeof(buffer), "%.*s%s%s", (int)(start - command), command, env_value, end);
            strcpy(command, buffer);
        }

        start = end;
    }
}

void execute_command(char *command)
{
    char *args[MAX_ARGS]; // Array to store command and its arguments
    char *token;
    int i = 0;
    int background = 0;

    // Check for redirection
    char *infile = NULL;            // Input file for redirection
    char *outfile = NULL;           // Output file for redirection
    char *appendfile = NULL;        // Output file for appending
    token = strtok(command, " \n"); // Tokenize the command string

    // Parse the command and its arguments
    while (token != NULL)
    {
        if (strcmp(token, "<") == 0)
        {
            infile = strtok(NULL, " \n"); // Get input filename
        }
        else if (strcmp(token, ">") == 0)
        {
            outfile = strtok(NULL, " \n"); // Get output filename
        }
        else if (strcmp(token, ">>") == 0)
        {
            appendfile = strtok(NULL, " \n"); // Get append filename
        }
        else if (strcmp(token, "&") == 0)
        {
            background = 1; // Set background flag
        }
        else
        {
            args[i++] = token; // Store command and arguments in the array
        }
        token = strtok(NULL, " \n"); // Get next token
    }
    args[i] = NULL; // Null-terminate the arguments array

    // Handle built-in commands
    if (strcmp(args[0], "cd") == 0)
    {
        if (args[1] == NULL || chdir(args[1]) != 0)
        {
            perror("cd");
        }
        return;
    }
    else if (strcmp(args[0], "pwd") == 0)
    {
        char cwd[MAX_LINE];
        if (getcwd(cwd, sizeof(cwd)) != NULL)
        {
            printf("%s\n", cwd);
        }
        else
        {
            perror("pwd");
        }
        return;
    }
    else if (strcmp(args[0], "echo") == 0)
    {
        for (int j = 1; args[j] != NULL; j++)
        {
            printf("%s ", args[j]);
        }
        printf("\n");
        return;
    }
    else if (strcmp(args[0], "alias") == 0)
    {
        if (args[1] == NULL)
        {
            for (int j = 0; j < alias_count; j++)
            {
                printf("alias %s='%s'\n", aliases[j].name, aliases[j].command);
            }
        }
        else
        {
            char *name = strtok(args[1], "=");
            char *command = strtok(NULL, "=");
            if (name && command)
            {
                aliases[alias_count].name = strdup(name);
                aliases[alias_count].command = strdup(command);
                alias_count++;
            }
        }
        return;
    }
    else if (strcmp(args[0], "unalias") == 0)
    {
        if (args[1] == NULL)
        {
            fprintf(stderr, "unalias: usage: unalias name\n");
        }
        else
        {
            for (int j = 0; j < alias_count; j++)
            {
                if (strcmp(aliases[j].name, args[1]) == 0)
                {
                    free(aliases[j].name);
                    free(aliases[j].command);
                    memmove(&aliases[j], &aliases[j + 1], (alias_count - j - 1) * sizeof(Alias));
                    alias_count--;
                    break;
                }
            }
        }
        return;
    }

    // Create a child process to execute the command
    pid_t pid = fork();
    if (pid == 0)
    {
        // Child process
        // Handle input redirection
        if (infile)
        {
            int in_fd = open(infile, O_RDONLY); // Open input file
            if (in_fd < 0)
            {
                perror("Failed to open input file");
                exit(EXIT_FAILURE);
            }
            dup2(in_fd, STDIN_FILENO); // Redirect standard input to the file
            close(in_fd);              // Close the file descriptor
        }

        // Handle output redirection
        if (outfile)
        {
            int out_fd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, 0644); // Open output file
            if (out_fd < 0)
            {
                perror("Failed to open output file");
                exit(EXIT_FAILURE);
            }
            dup2(out_fd, STDOUT_FILENO); // Redirect standard output to the file
            close(out_fd);               // Close the file descriptor
        }
        if (appendfile)
        {
            int append_fd = open(appendfile, O_WRONLY | O_CREAT | O_APPEND, 0644); // Open append file
            if (append_fd < 0)
            {
                perror("Failed to open append file");
                exit(EXIT_FAILURE);
            }
            dup2(append_fd, STDOUT_FILENO); // Redirect standard output to the file
            close(append_fd);               // Close the file descriptor
        }

        // Execute the command
        if (execvp(args[0], args) == -1)
        {
            fprintf(stderr, "Command not found: %s\n", args[0]); // More user-friendly error message
            exit(EXIT_FAILURE);
        }
    }
    else if (pid < 0)
    {
        perror("Failed to create process");
    }
    else
    {
        // Parent process
        if (!background)
        {
            wait(NULL); // Wait for child process to complete if not background
        }
    }
}

void execute_pipeline(char *command)
{
    char *commands[MAX_ARGS]; // Array to store individual commands in the pipeline
    int num_commands = 0;     // Number of commands in the pipeline

    // Split the pipeline command
    char *token = strtok(command, "|"); // Tokenize the command string by '|'
    while (token != NULL && num_commands < MAX_ARGS - 1)
    {
        commands[num_commands++] = token; // Store individual command
        token = strtok(NULL, "|");        // Get next token
    }
    commands[num_commands] = NULL; // Null-terminate the commands array

    int i;
    int pipe_fds[2];  // File descriptors for the pipe
    int prev_fd = -1; // Previous command's output file descriptor

    for (i = 0; i < num_commands; i++)
    {
        if (i < num_commands - 1)
        {
            if (pipe(pipe_fds) == -1)
            {
                perror("pipe");
                return;
            }
        }

        // Create a child process
        pid_t pid = fork();
        if (pid == 0)
        {
            // Child process
            if (prev_fd != -1)
            {
                dup2(prev_fd, STDIN_FILENO);
                close(prev_fd);
            }
            if (i < num_commands - 1)
            {
                close(pipe_fds[0]);
                dup2(pipe_fds[1], STDOUT_FILENO);
                close(pipe_fds[1]);
            }

            // Prepare the arguments for the command
            char *args[MAX_ARGS];
            int j = 0;
            token = strtok(commands[i], " \n");
            while (token != NULL)
            {
                args[j++] = token;
                token = strtok(NULL, " \n");
            }
            args[j] = NULL;

            // Special handling for "history" command
            if (strcmp(args[0], "history") == 0)
            {
                // Redirect history output to stdout
                for (int j = 0; j < history_count; j++)
                {
                    printf("%d %s", j + 1, history[j]);
                }
                fflush(stdout);
                exit(EXIT_SUCCESS);
            }

            if (execvp(args[0], args) == -1)
            {
                perror("execvp");
                exit(EXIT_FAILURE);
            }
        }
        else if (pid < 0)
        {
            perror("fork");
            return;
        }

        if (prev_fd != -1)
        {
            close(prev_fd);
        }
        if (i < num_commands - 1)
        {
            close(pipe_fds[1]);
            prev_fd = pipe_fds[0];
        }
    }

    // Wait for all child processes to complete
    for (i = 0; i < num_commands; i++)
    {
        wait(NULL);
    }
}

char *get_prompt(void)
{
    static char prompt[MAX_LINE];
    char hostname[256];
    char cwd[PATH_MAX];
    struct passwd *pw = getpwuid(getuid());

    gethostname(hostname, sizeof(hostname));
    getcwd(cwd, sizeof(cwd));

    // ensure null-terminated
    hostname[sizeof(hostname) - 1] = '\0';
    cwd[sizeof(cwd) - 1] = '\0';

    // get short username, hostname, and cwd
    char short_username[32], short_hostname[32], short_cwd[64];
    strncpy(short_username, pw->pw_name, sizeof(short_username) - 1);
    short_username[sizeof(short_username) - 1] = '\0';
    strncpy(short_hostname, hostname, sizeof(short_hostname) - 1);
    short_hostname[sizeof(short_hostname) - 1] = '\0';
    strncpy(short_cwd, cwd, sizeof(short_cwd) - 1);
    short_cwd[sizeof(short_cwd) - 1] = '\0';

    // create the prompt string
    snprintf(prompt, sizeof(prompt), "\033[1;32m%s@%s\033[0m:\033[1;34m%s\033[0m$ ",
             short_username, short_hostname, short_cwd);

    return prompt;
}

int main(void)
{
    print_welcome_message(); // Print welcome message

    char command[MAX_LINE]; // Buffer to store the command input

    // Set up signal handling
    signal(SIGINT, handle_signal);
    char *prompt = get_prompt();
    while (1)
    {
        printf("%s", prompt); // Print the prompt
        if (fgets(command, MAX_LINE, stdin) == NULL)
        {
            perror("Failed to read command");
            exit(EXIT_FAILURE);
        }

        // Skip if the input is empty or only contains whitespace
        if (command[0] == '\n')
        {
            continue;
        }

        // Add command to history
        add_to_history(command);

        // Check if the input is "exit"
        if (!strcmp(command, "exit\n"))
        {
            printf("Bye~😁😁\n");
            break; // Exit the loop
        }
        if (!strcmp(command, "history\n"))
        {
            show_history();
            continue;
        }
        if (!strcmp(command, "help\n"))
        {
            show_help();
            continue;
        }
        // Replace environment variables
        replace_env_vars(command);

        // Check if the command contains a pipeline
        if (strchr(command, '|'))
        {
            execute_pipeline(command); // Execute pipeline command
        }
        else
        {
            execute_command(command); // Execute regular command
        }
    }

    return EXIT_SUCCESS;
}