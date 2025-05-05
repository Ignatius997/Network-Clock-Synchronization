#include <stdio.h>
#include <inttypes.h>
#include <arpa/inet.h>

#include "../include/test.h"
#include "peer.h"
#include "clockman.h"

void test_peer_find_time(void) {
    clk_init();
        
    uint16_t i = 0;
    for (;;) {
        Peer p = {
            .peer_address_length = 4,
            .peer_address = {0},
            .peer_port = htons(PEER_MAX),
        };
        peer_add(&p);

        if (++i == PEER_MAX) break;
    } fprintf(stderr, "i=%" PRIu16 "\n", i);

    clk_update_tmp();
    fprintf(stderr, "Creation: "); // ~ 2 ms
    clk_print_tmp();
    clk_start_tmp();

    struct sockaddr_in s = {
        .sin_family = AF_INET,
        .sin_port = htons(PEER_MAX),
        .sin_addr.s_addr = htonl(1), // NOTE Shady.
    };
    Peer *p = peer_find(&s);

    clk_update_tmp();
    fprintf(stderr, "Find: "); // < 1 ms
    clk_print_tmp();

    peer_print(p);
}