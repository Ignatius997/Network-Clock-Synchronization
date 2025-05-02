#ifndef GLOBALS_H
#define GLOBALS_H

#include <stdint.h>

#define BUF_SIZE 65535 // FIXME Myślę, że więcej

extern int ncs_sockfd;
extern uint8_t ncs_buf[BUF_SIZE]; // Deklaracja globalnej zmiennej

void g_close_socket(void);

#endif // GLOBALS_H