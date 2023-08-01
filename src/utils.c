#include <fcntl.h>
#include <dlfcn.h>

#include "../include/utils.h"
#include "../include/procmem.h"

/*
 * Function: replace_long_long
 * ----------------------------
 *   Replace a long long value within a byte array with another
 *   long long value.
 *
 *   Parameters:
 *     bytes            byte array to replace in
 *     bytes_size       size of the byte array to replace in
 *     pattern          long long pattern to replace
 *     replace          long long value to replace with
 *
 *   Returns:
 *     number of repalced long long values
 */
int replace_long_long(char* bytes, size_t bytes_size, long long pattern, long long replace)
{
    int count = 0;

    for (int ctr = 0; ctr < bytes_size - 8; ctr++)
    {
        if (pattern == *(long long*)(bytes + ctr))
        {
            *(long long*)(bytes + ctr) = replace;
            count++;
            ctr += 7;
        }
    }

    return count;
}

/*
 * Function: search
 * ----------------------------
 *   Search a byte array for a long long value and return
 *   its offset.
 *
 *   Parameters:
 *     bytes            byte array to search in
 *     bytes_size       size of the byte array to search in
 *     pattern          long long pattern to search
 *
 *   Returns:
 *     offset of the pattern within the byte array
 */
long search(char* bytes, size_t size, long long pattern)
{
    for(long ctr = 0; ctr < size - 8; ctr++)
    {
        if (pattern == *(long long*)(bytes + ctr))
        {
            return ctr;
        }
    }

    return 0;
}

/*
 * Function: get_func_offset
 * ----------------------------
 *   Get the offset of the specified function within the specified
 *   library using the current process.
 *
 *   Parameters:
 *     libname:         library name where the function is defined
 *     funcname:        function name to search for
 *
 *   Returns:
 *     relative offset of the function within the library
 */
long get_func_offset(char* libname, char* funcname)
{
    long ret = 0;
    void *lib = dlopen(libname, RTLD_LAZY | RTLD_GLOBAL);

    if (!lib)
    {
        printf("[-] Unable to load '%s'\n", libname);
        return 0;
    }

    void *func_addr = dlsym(lib, funcname);

    if (func_addr)
    {
        long long lib_base = get_addr(getpid(), libname, "r-xp", 0);
        ret = (long)((long long)func_addr - lib_base);
    }

    dlclose(lib);
    return ret;
}
