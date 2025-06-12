#ifndef NETWORKING_H
#define NETWORKING_H
#include <stdint.h>
#include <sys/types.h>

/**
 * @brief Create a raw filter socket with the given BPF program.
 *
 * @param bpf Pointer to the BPF program to attach to the socket.
 * @return int The file descriptor of the created socket, or -1 on failure.
 */
int CreateRawFilterSocket(struct sock_fprog* bpf);
ssize_t RecvAndModifyPacket(int sock, uint16_t f_port, char* f_addr, char* s_addr,
                        unsigned char** packet);
int SendRawSocket(int sock, size_t packet_len, const unsigned char* packet, const char* interface);
int GetInterface(const char* address, char** interface);
#endif /*NETWORKING_H*/