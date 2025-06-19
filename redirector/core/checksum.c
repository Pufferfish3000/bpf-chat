#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>

#include "checksum.h"

//https://gist.github.com/GreenRecycleBin/1273762
uint16_t ip_checksum(struct ip* p_ip_header, size_t len)
{
    register int sum = 0;
    uint16_t* ptr = (unsigned short*)p_ip_header;
    uint16_t checksum = 0;

    while (len > 1)
    {
        sum += *ptr++;
        len -= 2;
    }

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);

    checksum = (uint16_t)~sum;

    return checksum;
}

//https://gist.github.com/GreenRecycleBin/1273763
uint16_t udp_checksum(struct udphdr* p_udp_header, size_t len, uint32_t src_addr,
                      uint32_t dest_addr)
{
    const uint16_t* buf = (const uint16_t*)p_udp_header;
    uint16_t *ip_src = (void*)&src_addr, *ip_dst = (void*)&dest_addr;
    uint32_t sum;
    size_t length = len;

    // Calculate the sum
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if (len & 1)
        // Add the padding if the packet lenght is odd
        sum += *((uint8_t*)buf);

    // Add the pseudo-header
    sum += *(ip_src++);
    sum += *ip_src;

    sum += *(ip_dst++);
    sum += *ip_dst;

    sum += htons(IPPROTO_UDP);
    sum += htons((uint16_t)length);

    // Add the carries
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum
    return (uint16_t)~sum;
}