//https://gist.github.com/GreenRecycleBin/1273762
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>

#include "checksum.h"

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