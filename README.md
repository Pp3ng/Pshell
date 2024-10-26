## A simple shell implementation in C

This is a simple shell implementation in C, designed to provide a command-line interface with various features and built-in commands.

### Features

- **Command Execution**: Execute standard Unix commands.
- **Pipelines**: Support for command pipelines (e.g., `ls | grep txt`).
- **Redirection**: Input and output redirection (e.g., `ls > output.txt`).
- **Command History**: Maintain a history of executed commands.
- **Aliases**: Create and use command aliases.
- **Environment Variables**: Use environment variables (e.g., `echo $PATH`).
- **Backend Commands**: Execute backend commands.
- **Prompt Execution Time**: Displays the execution time of the last command in the prompt.
- **Save/Load Aliases and History**: Automatically saves command aliases and history to files `.aliases` and `.history` and loads them when the shell starts.
- **Welcome Message and Help Command**: Displays a welcome message when the shell starts and includes a `help` command to show available commands and usage information.
- **Colorful Prompt**: Customizable colorful prompt for better visual distinction.
- **Wildcard Expansion**: Support for `*` and `?` wildcards in file name expansion.

## Built-in Commands

- `cd`: Change the current directory
- `pwd`: Print the current working directory
- `history`: Display or manipulate the command history
- `alias`: Define or display aliases
- `unalias`: Remove alias definitions
- `jobs`: List active jobs
- `exit`: Exit the shell
- `help`: Display help information about built-in commands

## Usage

1. Clone the repository
2. Compile: `gcc -o pshell pshell.c`
3. Run: `./pshell`
