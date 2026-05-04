/**
 * @file syscalls.c
 * @brief Minimal syscall stubs for embedded ARM
 * @note Provides minimal implementations for missing libc functions
 */
#include <stdio.h>
#include <sys/stat.h>

/* These are stub implementations for embedded systems */

/* _isatty - returns 1 for terminal devices */
int _isatty(int file)
{
    return 1;
}

/* _write - stub for write system call */
int _write(int file, char *ptr, int len)
{
    return len;
}

/* _read - stub for read system call */
int _read(int file, char *ptr, int len)
{
    return 0;
}

/* _close - stub for close system call */
int _close(int file)
{
    return 0;
}

/* _fstat - stub for fstat system call */
int _fstat(int file, struct stat *st)
{
    st->st_mode = S_IFCHR;
    return 0;
}

/* _lseek - stub for lseek system call */
int _lseek(int file, int ptr, int dir)
{
    return 0;
}

/* _exit - stub for exit */
void _exit(int status)
{
    while(1);
}

/* _getpid - stub for getpid */
int _getpid(void)
{
    return 1;
}

/* _kill - stub for kill */
int _kill(int pid, int sig)
{
    return -1;
}