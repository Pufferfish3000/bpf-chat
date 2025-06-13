#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "checksum.h"
#include "common.h"
#include "networking.h"
#include "rawparser.h"

ssize_t ParseEther(unsigned char* packet, ssize_t bytes_left)
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
ssize_t ParseIp(unsigned char* packet, ssize_t bytes_left, const char* d_addr, const char* s_addr)
{

    ssize_t parsed_bytes = -1;
    const ssize_t min_bytes = 20;
    uint16_t checksum = 0;
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
    ip_headr->ip_sum = 0;

    checksum = ip_checksum(ip_headr, (size_t)parsed_bytes);
    if (checksum == 0)
    {
        checksum = 0xFFFF;
    }
    ip_headr->ip_sum = checksum;

end:
    return parsed_bytes;
}

/**
 * @brief Parses the UDP header
 * 
 * @param packet pointer to the packet at the start of UDP
 * @param bytes_left the amount of bytes that can be parsed
 * @return ssize_t the amount of bytes actually parsed
 */
ssize_t ParseUdp(unsigned char* packet, ssize_t bytes_left, uint16_t f_port, uint16_t s_port,
                 struct ip* ip_header)
{
    ssize_t parsed_bytes = -1;
    const ssize_t min_bytes = 8;
    const char label[] = "udp  ";

    struct udphdr* udp_header = (struct udphdr*)packet;

    if (NULL == packet)
    {
        (void)fprintf(stderr, "packet can not be NULL\n");
        goto end;
    }
    if (NULL == ip_header)
    {
        (void)fprintf(stderr, "ip_header can not be NULL\n");
        goto end;
    }

    if (bytes_left < min_bytes)
    {
        (void)fprintf(stderr, "packet is too small\n");
        goto end;
    }

    udp_header->dest = htons(f_port);
    udp_header->source = htons(s_port);

    udp_header->check = 0;
    udp_header->check = udp_checksum(udp_header, ntohs(udp_header->len), ip_header->ip_src.s_addr,
                                     ip_header->ip_dst.s_addr);

    parsed_bytes = min_bytes;

    PrintHex(label, packet, (size_t)parsed_bytes);

end:
    return parsed_bytes;
}

int PrintHex(const char* label, const unsigned char* data, size_t length)
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
