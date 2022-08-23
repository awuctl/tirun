# tirun

Run a process with TrustedInstaller rights.

The spiritual successor to superUser. The goal of this is basically just to have a small executable.r

## Usage

To use `tirun` simply double-click it to open a *Command Prompt*.

Another option is to use the command line:

```
Usage: tirun [-w] [-h] [-c (COMMAND...)]

 -w: Wait for process to finish after running it
 -h: Show this help message
 -c: Specify command to run
```

**Note**: `tirun -w` does not wait for any children of the process you create, and therefore doesn't really work on forking processes.

## What is TrustedInstaller?

**TrustedInstaller** is a service in Vista and above Windows operating systems mainly responsible for managing the component store (*WinSxS*). Its most important function is **installing packages and updates**. 

Because of the very high permissions required to be able to **create** and **modify** system files, it is easily the most privileged entity on Windows - second to none but the kernel.

# Build from source
To build this, use `mingw32-make` from https://github.com/mstorsjo/llvm-mingw