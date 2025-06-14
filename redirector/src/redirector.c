#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "networking.h"
#include "redirector.h"

static int CreateUDPFilterSocket(uint16_t port);

int StartRedirector(uint16_t l_port, uint16_t f_port, char* f_addr, char* s_addr)
{
    int exit_code = EXIT_FAILURE;
    int sock = -1;
    unsigned char* packet = NULL;
    char* interface = NULL;
    ssize_t packet_len = -1;

    sock = CreateUDPFilterSocket(l_port);

    if (-1 == sock)
    {
        (void)fprintf(stderr, "Could not create raw udp filter socket\n");
        goto end;
    }

    if (GetInterface(s_addr, &interface))
    {
        (void)fprintf(stderr, "Could not get interface for address: %s\n", s_addr);
        goto end;
    }

    printf("Sending packets on interface: %s\n", interface);
    printf("Starting Redirector\n\n");
    packet_len = RecvAndModifyPacket(sock, f_port, l_port, f_addr, s_addr, &packet);

    if (-1 == packet_len)
    {
        (void)fprintf(stderr, "Could not Recv and Modify Packet\n");
        goto clean;
    }

    if (SendRawSocket(sock, (size_t)packet_len, packet, interface))
    {
        (void)fprintf(stderr, "Could not send raw socket\n");
        goto clean;
    }

    printf("SENDING %s:%d --> %s:%d\n", s_addr, l_port, f_addr, f_port);

clean:
    NFREE(interface);
    NFREE(packet);
    close(sock);

end:
    return exit_code;
}

/**
 * @brief Creates a raw UDP bpf socket that filters for UDP dst port.
 * 
 * @param port UDP dst port to filter for.
 * @return int the file descriptor of the created socket, or -1 on failure.
 */
static int CreateUDPFilterSocket(uint16_t port)
{
    int sock = -1;
    const short unsigned int code_size = 16;
    const int port_idx_1 = 5;
    const int port_idx_2 = 13;

    // udp and dst port = port
    struct sock_filter code[] = {
        {0x28, 0, 0, 0x0000000c},  {0x15, 0, 4, 0x000086dd}, {0x30, 0, 0, 0x00000014},
        {0x15, 0, 11, 0x00000011}, {0x28, 0, 0, 0x00000038}, {0x15, 8, 9, 0xffffffff},
        {0x15, 0, 8, 0x00000800},  {0x30, 0, 0, 0x00000017}, {0x15, 0, 6, 0x00000011},
        {0x28, 0, 0, 0x00000014},  {0x45, 4, 0, 0x00001fff}, {0xb1, 0, 0, 0x0000000e},
        {0x48, 0, 0, 0x00000010},  {0x15, 0, 1, 0xffffffff}, {0x6, 0, 0, 0x00040000},
        {0x6, 0, 0, 0x00000000},
    };

    code[port_idx_1].k = port;
    code[port_idx_2].k = port;

    struct sock_fprog bpf = {
        .len = code_size,
        .filter = code,
    };
    printf("Filtering packets for udp dst port: %u\n", port);

    sock = CreateRawFilterSocket(&bpf);
    if (-1 == sock)
    {
        (void)fprintf(stderr, "Could not create raw udp filter socket");
    }

    return sock;
}
