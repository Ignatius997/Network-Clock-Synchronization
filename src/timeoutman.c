#include <arpa/inet.h>

#include "../include/timeoutman.h"
#include "../include/sync.h"
#include "../include/peer.h"

void timeout_sync_start(const struct sockaddr_in *peer_address) {
    sync_reset(peer_address);
}

void timeout_delay(void) {

}