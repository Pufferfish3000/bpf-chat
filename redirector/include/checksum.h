#ifndef CHECKSUM_H
#define CHECKSUM_H
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>

uint16_t ip_checksum(struct ip* p_ip_header, size_t len);
uint16_t udp_checksum(struct udphdr* p_udp_header, size_t len, uint32_t src_addr,
                      uint32_t dest_addr);
#endif /*CHECKSUM_H*/