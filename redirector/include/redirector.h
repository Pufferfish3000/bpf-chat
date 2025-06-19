#ifndef REDIRECTOR_H
#define REDIRECTOR_H
#include <stdint.h>

int StartRedirector(uint16_t l_port, uint16_t f_port, int raw_send, char* f_addr, char* s_addr);
#endif /*REDIRECTOR_H*/