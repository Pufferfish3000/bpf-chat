#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
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
    struct ether_header* temp_eth = NULL;

    if (ether == NULL || *ether != NULL)
    {
        (void)fprintf(stderr, "Could not set socket options\n");
        goto end;
    }

    if (RecvAll(sock, (unsigned char**)&temp_eth, sizeof(*temp_eth)))
    {
        (void)fprintf(stderr, "Could not RecvAll ether header\n");
        goto clean;
    }

    *ether = temp_eth;
    exit_code = EXIT_SUCCESS;
    goto end;

clean:
    NFREE(temp_eth);

end:
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

    temp = calloc(
        recv_sz + 1,
        sizeof(
            *temp));  //ensures null termination, no effect on non strings due to how packets get handled
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
