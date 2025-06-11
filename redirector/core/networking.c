#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
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
static ssize_t ParseIp(unsigned char* packet, ssize_t bytes_left);
static int PrintHex(const char* label, const unsigned char* data, size_t length);

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

int RecvPacket(int sock)
{
    int exit_code = EXIT_FAILURE;
    unsigned char* packet = NULL;
    unsigned char* temp = NULL;
    ssize_t bytes_recv = -1;
    ssize_t bytes_parsed = -1;
    ssize_t pointer = 0;

    // hate doing this, but i run into many issues doing partial recvs with raw socket bpf, so
    // while I would prefer to recv ether size -> parse ether -> recv ip size etc, I cant
    packet = calloc(UINT16_MAX, sizeof(*packet));

    if (NULL == packet)
    {
        perror("calloc");
        goto end;
    }

    bytes_recv = recv(sock, packet, UINT16_MAX, 0);

    printf("recvd %ld bytes\n\n", bytes_recv);

    if (bytes_recv < 0)
    {
        (void)fprintf(stderr, "Failed to receive data on raw_sock\n");
        goto clean;
    }

    temp = realloc(packet, (size_t)bytes_recv * sizeof(*packet));

    // dont actually fail out from realloc, it doesnt change any logic, i just prefer to not be
    // a memory hog
    if (NULL != temp)
    {
        packet = temp;
    }

    // so because we had to unfortunately do one big recv, were going to have to parse the
    // header by tracking bytes left + pointer arithmetic

    bytes_parsed = ParseEther(packet, bytes_recv);

    if (-1 == bytes_parsed)
    {
        fprintf(stderr, "Could not parse ether header\n");
        goto clean;
    }

    pointer = pointer + bytes_parsed;
    bytes_recv = bytes_recv - bytes_parsed;

    bytes_parsed = ParseIp(packet + pointer, bytes_recv);

    if (-1 == bytes_parsed)
    {
        fprintf(stderr, "Could not parse ip header\n");
        goto clean;
    }

    pointer = pointer + bytes_parsed;

    exit_code = EXIT_SUCCESS;

    goto clean;

clean:
    NFREE(packet);
end:
    return exit_code;
}

/**
 * @brief Parses the ethernet packet, left for functionality if later i want to change ether 
 * fields
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

static ssize_t ParseIp(unsigned char* packet, ssize_t bytes_left)
{

    ssize_t parsed_bytes = -1;
    const ssize_t min_bytes = 20;
    const char label[] = "ip   ";

    struct ip* temp_headr = (struct ip*)packet;

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

    if (temp_headr->ip_v != 4)
    {
        fprintf(stderr, "field %d should be 4\n", temp_headr->ip_v);
        goto end;
    }

    if (temp_headr->ip_hl < 5)
    {
        fprintf(stderr, "Invalid IP header length: %d\n", temp_headr->ip_hl);
        goto end;
    }

    parsed_bytes = temp_headr->ip_hl * 4;

    if (parsed_bytes > bytes_left)
    {
        (void)fprintf(stderr, "ip data does not reflect bytes recv\n");
        goto end;
    }

    PrintHex(label, packet, (size_t)parsed_bytes);
    printf("IP src: %s\n", inet_ntoa(temp_headr->ip_src));
    printf("IP dst: %s\n", inet_ntoa(temp_headr->ip_dst));
    printf("Full IP header length: %lu\n", parsed_bytes);

end:
    return parsed_bytes;
}

static int PrintHex(const char* label, const unsigned char* data, size_t length)
{
    int exit_code = EXIT_FAILURE;
    const size_t hex = 16;

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

    for (size_t index = 0; index < length; ++index)
    {
        if (index % hex == 0)
            printf("%s %04zx : ", label, index);

        printf("%02x ", data[index]);

        if ((index + 1) % hex == 0)
            printf("\n");
    }

    if (length % hex != 0)
        printf("\n");

    printf("\n");

end:
    return exit_code;
}
