#include <string.h>
#include <unistd.h>

#include "../include/utils.h"
#include "../include/procmem.h"

/*
 * Function: procmem_open
 * ----------------------------
 *   Open a file descriptor for reading and writing /proc/pid/mem.
 *   The file descriptor returned needs to be closed by the caller.
 *
 *   Parameters:
 *     pid:     pid of the targeted process
 *
 *   Returns:
 *     file descriptor to /proc/pid/mem in O_RDWR mode
 */
int procmem_open(pid_t pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_RDWR);

    if (!fd)
    {
        printf("[-] Failed to open '%s' in read/write mode.\n", path);
        return -1;
    }

    return fd;
}

/*
 * Function: procmaps_open
 * ----------------------------
 *   Open the /proc/pid/maps file for reading. The returned FILE*
 *   needs to be closed by the caller.
 *
 *   Parameters:
 *     pid:     pid of the targeted process
 *
 *   Returns:
 *     FILE* for reading /proc/pid/maps
 */
FILE* procmaps_open(pid_t pid)
{
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    FILE* maps = fopen(path, "r");

    if (maps == NULL)
    {
        printf("[-] Unable to open '%s'\n", path);
    }

    return maps;
}

/*
 * Function: write_mem
 * ----------------------------
 *   Write memory using /proc/pid/mem. This function is also able
 *   to write non writable memory locations, as /proc/pid/mem bypasses
 *   such protections.
 *
 *   Parameters:
 *     procmem:     file descriptor to the /proc/pid/mem file
 *     addr         the virtual address to write to
 *     data         byte array to write to the specified address
 *     len          number of bytes to write
 *
 *   Returns:
 *     number of bytes actually written
 */
size_t write_mem(int procmem, unsigned long addr, char* data, size_t len)
{
    lseek(procmem, addr, SEEK_SET);
    return write(procmem, data, len);
}

/*
 * Function: read_mem
 * ----------------------------
 *   Read process memory bs using /proc/pid/mem. This function allocates
 *   a buffer for the obtained process memory data. This buffer needs to
 *   be freed by the callee.
 *
 *   Parameters:
 *     procmem:     file descriptor to the /proc/pid/mem file
 *     addr         the virtual address to read from
 *     len          number of bytes to read
 *
 *   Returns:
 *     buffer containing the obtained process data
 */
char* read_mem(int procmem, unsigned long addr, size_t len)
{
    char* data = (char*)malloc(len);

    if (!data)
    {
        printf("[-] Unable to allocate more memory\n");
        return NULL;
    }

    lseek(procmem, addr, SEEK_SET);
    read(procmem, data, len);

    return data;
}

/*
 * Function: get_addr
 * ----------------------------
 *   Get the address of the specified memory area using /proc/pid/maps.
 *   The desired area can be selected by using two strstr searches that
 *   utilize the name and perm parameters.
 *
 *   Parameters:
 *     pid:         process ID of the targeted process
 *     addr:        a library name to search for (e.g. libc)
 *     perm:        a permission set to search for (e.g. r-xp)
 *     nth:         get the nth matching entry
 *
 *   Returns:
 *     virtual address of a matching segment
 */
long long get_addr(pid_t pid, char* name, char* perm, int nth)
{
    int ctr = 0;
    size_t len = 0;
    char *line = NULL;
    ssize_t nread = 0;
    long long ret = 0;

    FILE* maps = procmaps_open(pid);

    if (maps == NULL)
    {
        return 0;
    }

    while ((nread = getline(&line, &len, maps)) != -1)
    {
        if (perm != NULL && !strstr(line, perm))
            continue;

        if (name != NULL && !strstr(line, name))
            continue;

        if (nth == NULL || nth == ctr)
        {
            ret = strtoull(line, NULL, 16);
            break;
        }

        ctr++;
    }

    free(line);
    fclose(maps);

    return ret;
}

/*
 * Function: get_size
 * ----------------------------
 *   Get the size of the specified memory area using /proc/pid/maps.
 *   The desired area can be selected by using two strstr searches that
 *   utilize the name and perm parameters.
 *
 *   Parameters:
 *     pid:         process ID of the targeted process
 *     addr:        a library name to search for (e.g. libc)
 *     perm:        a permission set to search for (e.g. r-xp)
 *     nth:         get the nth matching entry
 *
 *   Returns:
 *     size of a matching segment
 */
long get_size(pid_t pid, char* name, char* perm, int nth)
{
    size_t len = 0;
    char *line = NULL;
    char* token = NULL;

    int ctr = 0;
    ssize_t nread = 0;
    long long ret = 0;

    FILE* maps = procmaps_open(pid);

    if (maps == NULL)
    {
        return 0;
    }

    while ((nread = getline(&line, &len, maps)) != -1)
    {
        if (perm != NULL && !strstr(line, perm))
            continue;

        if (name != NULL && !strstr(line, name))
            continue;

        if (nth == NULL || nth == ctr)
        {
            ret = strtoull(line, NULL, 16);

            token = strtok(line, "-");
            token = strtok(NULL, "-");

            ret -= strtoull(token, NULL, 16);

            break;
        }

        ctr++;
    }

    free(line);
    fclose(maps);

    return (long)-ret;
}

/*
 * Function: find_code_cave
 * ----------------------------
 *   Find a code cave of the specified length within a section with the
 *   specified permissions.
 *
 *   Parameters:
 *     procmem:     file descriptor to the /proc/pid/mem file
 *     pid:         process ID of the targeted process
 *     cave_size:   minimum size of the codek
 *     perm:        desired permission mask of the cave.
 *
 *   Returns:
 *     virtual address of a code cave within the remote process
 */
long long find_code_cave(int procmem, pid_t pid, int cave_size, char* perm)
{
    size_t len = 0;
    char *line = NULL;
    char *token = NULL;
    ssize_t nread = 0;

    long long addr = 0;
    long long cave = 0;

    FILE* maps = procmaps_open(pid);

    if (maps == NULL)
    {
        return 0;
    }

    while ((nread = getline(&line, &len, maps)) != -1)
    {
        if (!strstr(line, perm))
            continue;

        addr = strtoll(line, NULL, 16);

        token = strtok(line, "-");
        token = strtok(NULL, "-");

        long size = strtoll(token, NULL, 16) - addr;
        char* data = read_mem(procmem, addr, size);

        for (int ctr = 0; ctr < size; ctr++)
        {
            int all_zero = 1;

            for (int cts = 0; cts < cave_size; cts++)
            {
                if (data[ctr + cts] != 0x00)
                {
                    all_zero = 0;
                    break;
                }
            }

            if (all_zero)
            {
                cave = addr + ctr;
                break;
            }
        }

        if (cave != 0)
            break;
    }

    free(line);
    fclose(maps);

    return cave;
}
