#ifndef UTILS
#define UTILS

#include <stdio.h>
#include <stdlib.h>

int replace_long_long(char* bytes, size_t bytes_size, long long pattern, long long replace);
long search(char* bytes, size_t byte_size, long long pattern);
long get_func_offset(char* libname, char* funcname);

#endif
