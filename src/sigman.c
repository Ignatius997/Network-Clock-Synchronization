#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include "../include/sigman.h"
#include "../include/peer.h"
#include "../include/globals.h"
#include "../include/err.h"

static void sig_handle_sigint(int sig) {
    fprintf(stderr, "\nCaught signal %d (SIGINT). Closing socket and exiting...\n", sig);
    g_close_socket();
    exit(130);
}

static void sig_handle_quit(int sig) {
    fprintf(stderr, "\nCaught signal %d (EOF). Printing all peers:\n", sig);
    for (uint16_t i = 0; i < peer_get_count(); ++i) {
        peer_print(&peer_get_all()[i]);
    }
    fprintf(stderr, "\n");
    g_close_socket();
    exit(1);
}

void sig_setup_signal_handler(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    // Handle SIGINT handler.
    sa.sa_handler = sig_handle_sigint;
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        syserr("sigaction failed for SIGINT");
    }

    // Add SIGQUIT handler.
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handle_quit;
    if (sigaction(SIGQUIT, &sa, NULL) < 0) {
        syserr("sigaction failed for SIGQUIT");
    }
}
