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
static int RawSendLoop(uint16_t l_port, uint16_t f_port, char* f_addr, char* s_addr);
static int UdpSendLoop(uint16_t l_port, uint16_t f_port, char* f_addr, char* s_addr);
int StartRedirector(uint16_t l_port, uint16_t f_port, int raw_send, char* f_addr, char* s_addr)
{
    int exit_code = EXIT_FAILURE;

    if (raw_send)
    {
        exit_code = RawSendLoop(l_port, f_port, f_addr, s_addr);
    }
    else
    {
        exit_code = UdpSendLoop(l_port, f_port, f_addr, s_addr);
    }

    return exit_code;
}

static int RawSendLoop(uint16_t l_port, uint16_t f_port, char* f_addr, char* s_addr)
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
    packet_len = RecvAndModifyPacket(sock, f_port, l_port, NULL, f_addr, s_addr, &packet);

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

static int UdpSendLoop(uint16_t l_port, uint16_t f_port, char* f_addr, char* s_addr)
{
    int exit_code = EXIT_FAILURE;
    int bpf_sock = -1;
    int udp_sock = -1;
    unsigned char* data = NULL;

    unsigned char* packet = NULL;
    ssize_t packet_len = -1;
    struct sockaddr_in dest_addr = {0};
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(f_port);

    if (inet_pton(AF_INET, f_addr, &dest_addr.sin_addr) <= 0)
    {
        (void)fprintf(stderr, "Invalid address: %s\n", f_addr);
        goto clean;
    }
    bpf_sock = CreateUDPFilterSocket(l_port);

    if (-1 == bpf_sock)
    {
        (void)fprintf(stderr, "Could not create raw udp filter socket\n");
        goto end;
    }

    udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == udp_sock)
    {
        (void)fprintf(stderr, "Could not create UDP socket\n");
        goto clean;
    }

    printf("Starting Redirector\n\n");
    packet_len = RecvAndModifyPacket(bpf_sock, f_port, l_port, &data, f_addr, s_addr, &packet);

    if (-1 == packet_len)
    {
        (void)fprintf(stderr, "Could not Recv and Modify Packet\n");
        goto clean;
    }

    if (NULL == data)
    {
        (void)fprintf(stderr, "Data section is NULL\n");
        goto clean;
    }
    if (sendto(udp_sock, data, (size_t)packet_len, 0, (struct sockaddr*)&dest_addr,
               sizeof(dest_addr)) < 0)
    {
        (void)fprintf(stderr, "Could not send UDP packet\n");
        goto clean;
    }
    printf("SENDING %s:%d --> %s:%d\n", s_addr, l_port, f_addr, f_port);

clean:
    NFREE(packet);
    close(bpf_sock);

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
