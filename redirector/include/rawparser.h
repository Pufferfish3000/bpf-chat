#ifndef RAWPARSER_H
#define RAWPARSER_H
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stddef.h>
#include <stdint.h>

ssize_t ParseEther(unsigned char* packet, ssize_t bytes_left);
ssize_t ParseIp(unsigned char* packet, ssize_t bytes_left, const char* d_addr, const char* s_addr);
ssize_t ParseUdp(unsigned char* packet, ssize_t bytes_left, uint16_t f_port, uint16_t s_port,
                 struct ip* ip_header);
int PrintHex(const char* label, const unsigned char* data, size_t length);

#endif /*RAWPARSER_H*/