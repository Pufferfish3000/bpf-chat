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
int RecvPacket(int sock);
#endif /*NETWORKING_H*/