#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <netinet/ip.h>
#include <stddef.h>
#include <stdint.h>

uint16_t ip_checksum(struct ip* p_ip_header, size_t len);

#endif /*CHECKSUM_H*/