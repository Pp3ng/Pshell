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

### Built-in Commands

- **cd**: Change the current working directory.
- **history**: Display the command history.
- **alias**: Create and use command aliases.
- **echo $VAR**: Display the value of an environment variable.
- **exit**: Exit the shell.
