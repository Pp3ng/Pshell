## A simple shell implementation in C

This is a simple shell implementation in C. Shell is a command interpreter that provides a command-line user interface for Unix-like operating systems. The shell is both an interactive command language and a scripting language, and is used by the operating system to control the execution of the system using shell scripts.

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

### Built-in Commands

- **cd**: Change the current working directory.
- **pwd**: Print the current working directory.
- **ls [options]**: List directory contents.
- **history**: Display the command history.
- **alias**: Create and use command aliases.
- **unalias name**: Remove an alias.
- **echo $VAR**: Display the value of an environment variable.
- **exit**: Exit the shell.
- **help**: Display available commands and usage information.
