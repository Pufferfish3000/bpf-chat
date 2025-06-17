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
#include "rawparser.h"

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

ssize_t RecvAndModifyPacket(int sock, uint16_t f_port, uint16_t s_port, char* f_addr, char* s_addr,
                            unsigned char** packet)
{
    ssize_t exit_code = -1;
    ssize_t bytes_parsed = -1;
    ssize_t bytes_recv = -1;
    ssize_t pointer = 0;

    (void)f_port;

    unsigned char* temp_packet = NULL;
    unsigned char* temp = NULL;

    struct ip* ip_ptr = NULL;

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

    ip_ptr = (struct ip*)(temp_packet + pointer);

    pointer = pointer + bytes_parsed;
    bytes_recv = bytes_recv - bytes_parsed;

    bytes_parsed = ParseUdp(temp_packet + pointer, bytes_recv, f_port, s_port, ip_ptr);

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

int SendUDP(unsigned char* packet, size_t packet_len, int sock, struct sockaddr_in* addr)
{
    int exit_code = EXIT_FAILURE;
    struct sockaddr_in server_addr = {0};

    if (NULL == packet)
    {
        (void)fprintf(stderr, "packet can not be NULL\n");
        goto end;
    }

    if (packet_len <= 0)
    {
        (void)fprintf(stderr, "packet_len must be greater than 0\n");
        goto end;
    }

    if (sendto(sock, packet, packet_len, 0, (struct sockaddr*)&server_addr, sizeof(server_addr)) <
        0)
    {
        perror("sendto failed");
        goto end;
    }

    exit_code = EXIT_SUCCESS;

end:
    return exit_code;
}

int CreateUdpSocket()
{
    int sock = -1;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("Could not create UDP socket");
        return -1;
    }

    return sock;
}