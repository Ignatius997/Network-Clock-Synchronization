#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include "../include/globals.h"

/**
 * Naming convention: nsc_{name} (nsc from netclocksync).
 */
int     ncs_sockfd = -1; // ofc host order
uint8_t ncs_buf[G_BUF_SIZE] = {0}; // Definicja globalnej zmiennej

void g_close_socket() {
    if (ncs_sockfd >= 0) {
        close(ncs_sockfd);
        fprintf(stderr, "Socket closed.\n");
    }
}
