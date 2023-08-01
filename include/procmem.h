#ifndef PROCMEM
#define PROCMEM

#include <stdio.h>
#include <fcntl.h>

int procmem_open(pid_t pid);
FILE* procmaps_open(pid_t pid);
long long get_addr(pid_t pid, char* name, char* perm, int nth);
long get_size(pid_t pid, char* name, char* perm, int nth);
char* read_mem(int procmem, unsigned long addr, size_t len);
size_t write_mem(int procmem, unsigned long addr, char* data, size_t len);
long long find_code_cave(int procmem, pid_t pid, int cave_size, char* perm);

#endif
