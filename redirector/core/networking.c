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
static int RecvAll(int sock, unsigned char** raw_bytes, size_t recv_sz);
static int RecvEther(int sock, struct ether_header** ether);
static int RecvIp(int sock, unsigned char** ip_header);
static void PrintHex(const unsigned char* data, size_t length);

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
    struct ether_header* ether = NULL;
    unsigned char* ip_header = NULL;

    if (RecvIp(sock, &ip_header))
    {
        (void)fprintf(stderr, "Could not recv ip\n");
    }

    if (RecvEther(sock, &ether))
    {
        (void)fprintf(stderr, "Could not recv ether header\n");
        goto end;
    }
    exit_code = EXIT_SUCCESS;

    goto clean;

clean:
    NFREE(ether);
end:
    return exit_code;
}

static int RecvEther(int sock, struct ether_header** ether)
{
    int exit_code = EXIT_FAILURE;
    unsigned char* buffer = NULL;

    if (ether == NULL || *ether != NULL)
    {
        (void)fprintf(stderr, "Could not set socket options\n");
        goto end;
    }

    if (RecvAll(sock, &buffer, 20))
    {
        (void)fprintf(stderr, "Could not RecvAll ether header\n");
        goto end;
    }

    printf("ether\n");

    PrintHex(buffer, 20);

    *ether = (struct ether_header*)buffer;
    exit_code = EXIT_SUCCESS;
    goto end;

end:
    return exit_code;
}

// static int RecvIp(int sock, unsigned char** ip_header)
// {
//     int exit_code = EXIT_FAILURE;
//     const size_t min_bytes = 20;
//     size_t remaining_bytes = 0;

//     struct ip* temp_headr = NULL;

//     (void)ip_header;

//     unsigned char* buffer = NULL;

//     if (RecvAll(sock, &buffer, min_bytes))
//     {
//         (void)fprintf(stderr, "Could not RecvAll first 20 bytes of IP\n");
//         goto clean;
//     }

//     temp_headr = (struct ip*)buffer;
//     remaining_bytes = temp_headr->ip_hl * 4;
//     remaining_bytes = remaining_bytes - min_bytes;

//     printf("Remaining bytes %ld\n", remaining_bytes);
//     printf("IP src: %s\n", inet_ntoa(temp_headr->ip_src));
//     printf("IP dst: %s\n", inet_ntoa(temp_headr->ip_dst));

//     goto end;
// clean:
//     NFREE(temp_headr);

// end:
//     return exit_code;
// }

static int RecvIp(int sock, unsigned char** ip_header)
{
    int exit_code = EXIT_FAILURE;
    const size_t min_bytes = 20;

    unsigned char* buffer = NULL;

    (void)ip_header;

    if (RecvAll(sock, &buffer, 34))
    {
        fprintf(stderr, "Could not RecvAll first 20 bytes of IP\n");
        goto clean;
    }
    printf("ip\n");

    PrintHex(buffer, 34);

    struct ip* temp_headr = (struct ip*)buffer + 14;

    printf("iasdasdp\n");

    PrintHex((unsigned char*)temp_headr, 20);

    if (temp_headr->ip_v != 4)
    {
        fprintf(stderr, "field %d should be 4\n", temp_headr->ip_v);
        goto clean;
    }

    if (temp_headr->ip_hl < 5)
    {
        fprintf(stderr, "Invalid IP header length: %d\n", temp_headr->ip_hl);
        goto clean;
    }

    size_t full_header_len = temp_headr->ip_hl * 4;

    if (full_header_len > min_bytes)
    {
        unsigned char* extended = realloc(buffer, full_header_len);
        if (!extended)
        {
            fprintf(stderr, "Failed to realloc for full IP header\n");
            goto clean;
        }

        ssize_t extra = recv(sock, extended + min_bytes, full_header_len - min_bytes, 0);
        if (extra != (ssize_t)(full_header_len - min_bytes))
        {
            fprintf(stderr, "Failed to receive full IP header\n");
            NFREE(extended);
            goto clean;
        }

        buffer = extended;
        temp_headr = (struct ip*)buffer;
    }

    printf("IP src: %s\n", inet_ntoa(temp_headr->ip_src));
    printf("IP dst: %s\n", inet_ntoa(temp_headr->ip_dst));
    printf("Full IP header length: %lu\n", full_header_len);

    exit_code = EXIT_SUCCESS;

clean:
    NFREE(buffer);
    return exit_code;
}

static int RecvAll(int sock, unsigned char** raw, size_t recv_sz)
{
    int exit_code = EXIT_FAILURE;

    size_t total_recv = 0;
    ssize_t this_bytes = 0;

    unsigned char* temp = NULL;

    if (NULL == raw || NULL != *raw)
    {
        (void)fprintf(stderr, "raw must be a NULL double pointer");
        goto end;
    }

    temp = calloc(recv_sz, sizeof(*temp));
    if (NULL == temp)
    {
        (void)fprintf(stderr, "failed to calloc temp");
        goto end;
    }

    while (total_recv < recv_sz)
    {
        this_bytes = recv(sock, temp + total_recv, recv_sz - total_recv, 0);

        if (this_bytes <= 0)
        {
            (void)fprintf(stderr, "recv failed");
            goto clean;
        }

        total_recv += (size_t)this_bytes;
    }

    *raw = temp;
    exit_code = EXIT_SUCCESS;
    goto end;

clean:
    NFREE(temp);

end:
    return exit_code;
}

static void PrintHex(const unsigned char* data, size_t length)
{
    for (size_t i = 0; i < length; ++i)
    {
        if (i % 16 == 0)
            printf("%04zx : ", i);

        printf("%02x ", data[i]);

        if ((i + 1) % 16 == 0)
            printf("\n");
    }

    if (length % 16 != 0)
        printf("\n");
}
