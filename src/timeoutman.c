#include <arpa/inet.h>
#include <sys/time.h>

#include "../include/timeoutman.h"
#include "../include/sync.h"
#include "../include/peer.h"
#include "../include/message.h"
#include "../include/globals.h"
#include "../include/err.h"

static struct timeval sync_start_timeout = {
    .tv_sec = 20,
    .tv_usec = 0,
};

static struct timeval delay_timeout = {
    .tv_sec = 5,
    .tv_usec = 0,
};

static void _set(const struct timeval *timeout) {
    if (setsockopt(ncs_sockfd, SOL_SOCKET, SO_RCVTIMEO, timeout, sizeof(*timeout)) < 0) {
        // TODO Handle it.
        syserr("setsockopt");
    }
}

void timeout_sync_start(const struct sockaddr_in *peer_address) {
    sync_cancel();
}

void timeout_set(void) {
    struct timeval *timeout;

    switch (sync_get_exp_msg()) {
        case MSG_SYNC_START:
            timeout = &sync_start_timeout;
            break;

        default:
            timeout = NULL;
            break;
    }

    if (timeout != NULL) _set(timeout);
}

void timeout_delay(void) {
    sync_set_exp_msg(MSG_SYNC_START);
}