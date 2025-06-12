#include <arpa/inet.h>
#include <features.h>
#include <ifaddrs.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "networking.h"
static ssize_t ParseEther(unsigned char* packet, ssize_t bytes_left);
static ssize_t ParseIp(unsigned char* packet, ssize_t bytes_left, const char* d_addr,
                       const char* s_addr);
static ssize_t ParseUdp(unsigned char* packet, ssize_t bytes_left);
static int PrintHex(const char* label, const unsigned char* data, size_t length);

int SendRawSocket(int sock, size_t packet_len, const unsigned char* packet, const char* interface)
{
    int exit_code = EXIT_FAILURE;
    struct sockaddr_ll device = {0};
    unsigned int interface_index = 0;

    if (NULL == packet)
    {
        (void)fprintf(stderr, "packet can not be NULL\n");
        goto end;
    }
    if (NULL == interface)
    {
        (void)fprintf(stderr, "interface can not be NULL\n");
        goto end;
    }
    if (packet_len <= 0)
    {
        (void)fprintf(stderr, "packet_len must be greater than 0\n");
        goto end;
    }
    if (sock < 0)
    {
        (void)fprintf(stderr, "sock must be a valid socket\n");
        goto end;
    }

    interface_index = if_nametoindex(interface);
    if (0 == interface_index)
    {
        (void)fprintf(stderr, "Could not get interface index for: %s\n", interface);
        goto end;
    }

    device.sll_family = AF_PACKET;
    device.sll_protocol = htons(ETH_P_ALL);
    device.sll_ifindex = (int)interface_index;

    if (-1 == sendto(sock, packet, packet_len, 0, (struct sockaddr*)&device, sizeof(device)))
    {
        perror("sendto failed");
    }

    exit_code = EXIT_SUCCESS;

end:

    return exit_code;
}

int CreateRawFilterSocket(struct sock_fprog* bpf)
{
    int sock = -1;

    const int recv_timeout = 10;
    struct timeval time_val = {.tv_sec = recv_timeout, .tv_usec = 0};
    if (NULL == bpf)
    {
        (void)fprintf(stderr, "bpf can not be NULL\n");
        goto end;
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (-1 == sock)
    {
        (void)fprintf(stderr, "Could not create raw sock\n");
        goto end;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, bpf, sizeof(*bpf)))
    {
        perror("setsockopt failed");
        (void)fprintf(stderr, "Could not set socket options\n");
        goto clean;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&time_val, sizeof(time_val)))
    {
        (void)fprintf(stderr, "Could not set receive timeout\n");
        goto clean;
    }

    goto end;

clean:
    close(sock);
    sock = -1;
end:
    return sock;
}

ssize_t RecvAndModifyPacket(int sock, uint16_t f_port, char* f_addr, char* s_addr,
                            unsigned char** packet)
{
    ssize_t exit_code = -1;
    ssize_t bytes_parsed = -1;
    ssize_t bytes_recv = -1;
    ssize_t pointer = 0;

    (void)f_port;

    unsigned char* temp_packet = NULL;
    unsigned char* temp = NULL;

    const char label[] = "data ";

    if (NULL == f_addr)
    {
        (void)fprintf(stderr, "f_addr can not be NULL\n");
        goto end;
    }

    if (NULL == s_addr)
    {
        (void)fprintf(stderr, "s_addr can not be NULL\n");
        goto end;
    }

    if (NULL == packet || NULL != *packet)
    {
        (void)fprintf(stderr, "packet must be a NULL double pointer\n");
        goto end;
    }

    // hate doing this, but i run into many issues doing partial recvs with raw socket bpf, so
    // while I would prefer to recv ether size -> parse ether -> recv ip size etc, I cant
    temp_packet = calloc(UINT16_MAX, sizeof(*temp_packet));

    if (NULL == temp_packet)
    {
        perror("calloc");
        goto end;
    }

    bytes_recv = recv(sock, temp_packet, UINT16_MAX, 0);

    if (bytes_recv < 0)
    {
        (void)fprintf(stderr, "Failed to receive data on raw_sock\n");
        goto clean;
    }

    temp = realloc(temp_packet, (size_t)bytes_recv * sizeof(*temp_packet));

    // dont actually fail out from realloc, it doesnt change any logic, i just prefer to not be
    // a memory hog
    if (NULL != temp)
    {
        temp_packet = temp;
    }

    // so because we had to unfortunately do one big recv, were going to have to parse the
    // header by tracking bytes left + pointer arithmetic

    bytes_parsed = ParseEther(temp_packet, bytes_recv);

    if (-1 == bytes_parsed)
    {
        (void)fprintf(stderr, "Could not parse ether header\n");
        goto clean;
    }

    pointer = pointer + bytes_parsed;
    bytes_recv = bytes_recv - bytes_parsed;

    bytes_parsed = ParseIp(temp_packet + pointer, bytes_recv, f_addr, s_addr);

    if (-1 == bytes_parsed)
    {
        (void)fprintf(stderr, "Could not parse ip header\n");
        goto clean;
    }

    pointer = pointer + bytes_parsed;
    bytes_recv = bytes_recv - bytes_parsed;

    bytes_parsed = ParseUdp(temp_packet + pointer, bytes_recv);

    if (-1 == bytes_parsed)
    {
        (void)fprintf(stderr, "Could not parse ip header\n");
        goto clean;
    }

    pointer = pointer + bytes_parsed;
    bytes_recv = bytes_recv - bytes_parsed;

    if (bytes_recv > 0)
    {
        PrintHex(label, temp_packet + pointer, (size_t)bytes_recv);
    }

    exit_code = pointer + bytes_recv;
    *packet = temp_packet;

    goto end;

clean:
    NFREE(temp_packet);
end:
    return exit_code;
}

/**
 * @brief Parses the ethernet header
 * 
 * @param packet pointer to the packet at the start of the ethernet
 * @param bytes_left the amount of bytes that can be parsed
 * @return ssize_t the amount of bytes actually parsed
 */
static ssize_t ParseEther(unsigned char* packet, ssize_t bytes_left)
{
    ssize_t parsed_bytes = -1;
    const int eth_sz = 14;
    const char label[] = "ether";

    if (NULL == packet)
    {
        (void)fprintf(stderr, "packet can not be NULL\n");
        goto end;
    }

    if (bytes_left < eth_sz)
    {
        (void)fprintf(stderr, "packet is too small\n");
        goto end;
    }

    PrintHex(label, packet, (size_t)eth_sz);

    parsed_bytes = eth_sz;
    goto end;

end:
    return parsed_bytes;
}

/**
 * @brief Parses the IP header
 * 
 * @param packet pointer to the packet at the start of IP
 * @param bytes_left the amount of bytes that can be parsed
 * @return ssize_t the amount of bytes actually parsed
 */
static ssize_t ParseIp(unsigned char* packet, ssize_t bytes_left, const char* d_addr,
                       const char* s_addr)
{

    ssize_t parsed_bytes = -1;
    const ssize_t min_bytes = 20;

    const char label[] = "ip   ";

    struct in_addr src = {0};
    struct in_addr dst = {0};

    struct ip* ip_headr = (struct ip*)packet;

    if (NULL == packet)
    {
        (void)fprintf(stderr, "packet can not be NULL\n");
        goto end;
    }

    if (bytes_left < min_bytes)
    {
        (void)fprintf(stderr, "packet is too small\n");
        goto end;
    }

    if (ip_headr->ip_v != 4)
    {
        (void)fprintf(stderr, "field %d should be 4\n", ip_headr->ip_v);
        goto end;
    }

    if (ip_headr->ip_hl < 5)
    {
        (void)fprintf(stderr, "Invalid IP header length: %d\n", ip_headr->ip_hl);
        goto end;
    }

    parsed_bytes = (ssize_t)ip_headr->ip_hl * 4;

    if (parsed_bytes > bytes_left)
    {
        (void)fprintf(stderr, "ip data does not reflect bytes recv\n");
        goto end;
    }

    PrintHex(label, packet, (size_t)parsed_bytes);

    if (inet_aton(s_addr, &src) == 0)
    {
        (void)fprintf(stderr, "Invalid source IP: %s\n", s_addr);
        goto end;
    }

    if (inet_aton(d_addr, &dst) == 0)
    {
        (void)fprintf(stderr, "Invalid destination IP: %s\n", d_addr);
        goto end;
    }

    ip_headr->ip_src = src;
    ip_headr->ip_dst = dst;

end:
    return parsed_bytes;
}

int GetInterface(const char* address, char** interface)
{
    int exit_code = EXIT_FAILURE;

    unsigned int if_index = 0;
    char* temp = NULL;
    struct ifaddrs* ifaddr = NULL;
    struct ifaddrs* ifa = NULL;
    int found = 0;

    if (NULL == address)
    {
        (void)fprintf(stderr, "address can not be NULL\n");
        goto end;
    }

    if (NULL == interface || NULL != *interface)
    {
        (void)fprintf(stderr, "interface must be a NULL double pointer\n");
        goto end;
    }

    if (getifaddrs(&ifaddr) == -1)
    {
        perror("getifaddrs");
        goto end;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET)
        {
            char host[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &((struct sockaddr_in*)ifa->ifa_addr)->sin_addr, host,
                          sizeof(host)))
            {
                if (strcmp(host, address) == 0)
                {
                    if_index = if_nametoindex(ifa->ifa_name);
                    found = 1;
                    break;
                }
            }
        }
    }

    freeifaddrs(ifaddr);

    if (!found || 0 == if_index)
    {
        (void)fprintf(stderr, "Could not get interface index for address: %s\n", address);
        goto end;
    }

    temp = calloc(IF_NAMESIZE, sizeof(*temp));
    if (NULL == temp)
    {
        perror("calloc");
        goto end;
    }

    if (NULL == if_indextoname(if_index, temp))
    {
        (void)fprintf(stderr, "Could not get interface name for address: %s\n", address);
        goto clean;
    }

    *interface = temp;
    exit_code = EXIT_SUCCESS;
    goto end;

clean:
    NFREE(temp);

end:
    return exit_code;
}

/**
 * @brief Parses the UDP header
 * 
 * @param packet pointer to the packet at the start of UDP
 * @param bytes_left the amount of bytes that can be parsed
 * @return ssize_t the amount of bytes actually parsed
 */
static ssize_t ParseUdp(unsigned char* packet, ssize_t bytes_left)
{
    ssize_t parsed_bytes = -1;
    const ssize_t min_bytes = 8;
    const char label[] = "udp  ";

    if (NULL == packet)
    {
        (void)fprintf(stderr, "packet can not be NULL\n");
        goto end;
    }

    if (bytes_left < min_bytes)
    {
        (void)fprintf(stderr, "packet is too small\n");
        goto end;
    }

    parsed_bytes = min_bytes;

    PrintHex(label, packet, (size_t)parsed_bytes);

end:
    return parsed_bytes;
}

static int PrintHex(const char* label, const unsigned char* data, size_t length)
{
    int exit_code = EXIT_FAILURE;
    const size_t hex = 16;
    size_t index = 0;

    if (NULL == data)
    {
        (void)fprintf(stderr, "data can not be NULL\n");
        goto end;
    }

    if (NULL == label)
    {
        (void)fprintf(stderr, "label can not be NULL\n");
        goto end;
    }

    for (index = 0; index < length; ++index)
    {
        if (index % hex == 0)
            printf("%s  ", label);

        printf("%02x ", data[index]);

        if ((index + 1) % hex == 0)
            printf("\n");
    }

    if (length % hex != 0)
        printf("\n");

end:
    return exit_code;
}
