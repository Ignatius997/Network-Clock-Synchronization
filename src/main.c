#include <stdint.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <regex.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <signal.h>
#include <endian.h>
#include <time.h>

#include <unistd.h>

#include "../include/peer.h"
#include "../include/netutil.h"
#include "../include/err.h"
#include "../include/args.h"
#include "../include/sigman.h"
#include "../include/message.h"
#include "../include/loglib.h"
#include "../include/handler.h"
#include "../include/send.h"
#include "../include/globals.h"
#include "../include/clockman.h"
#include "../include/test.h"

// NOTE Tak naprawdę nie są to żadne fazy programu, lecz momenty do timeoutów
// NOTE Widać, że potrzebujemy biblioteki do timeout-ów
#define PHASE_JOIN 0
#define PHASE_AWAIT_SYNC 

int phase = PHASE_JOIN;

// TODO Gdzie dać receive_message? netrecv.h?
// NOTE Użycie ncs_buf pokazuje, że definicja tej funkcji powinna być poza mainem.
// NOTE ncs_buf ma być z idei ukryty.
ssize_t receive_message(struct sockaddr_in *peer_address) {
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    ssize_t recv_len = recvfrom(ncs_sockfd, ncs_buf, sizeof(ncs_buf), 0,
                                (struct sockaddr *) peer_address, &addr_len);
    return nutil_validate_received_data(peer_address, recv_len);
}

void join_network(const ProgramArgs *args) {
    if (!args->_ar_provided) return;

    struct sockaddr_in peer_address;
    nutil_set_address(args->peer_address, htons(args->peer_port), &peer_address);
    
    Peer first;
    first.peer_address_length = NUTIL_IPV4_ADDR_LEN;
    if (inet_pton(AF_INET, args->peer_address, first.peer_address) != 1) {
        syserr("inet_pton failed");
    }
    first.peer_port = htons(args->peer_port);
    peer_add(&first);

    SendInfo sinfo = {
        .len = -1,
        .peer_address = peer_address,
    };
    send_hello(&sinfo);
}

void listen_for_messages(void) {
    struct sockaddr_in peer_address;

    while (true) {
        ssize_t recv_len = receive_message(&peer_address);
        if (recv_len != -1) { // recvfrom success
            handle_message(&peer_address, recv_len);
        } else { // recvfrom fail or socket timeout
            handle_recv_fail(&peer_address);
        }
    }
}

int main(int argc, char* argv[]) {
    clk_init();
    sig_setup_signal_handler(); // Just for debugging I guess.

    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);
    args_print(&program_args);
    args_validate(&program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    nutil_init_socket(&bind_address, program_args.bind_address, program_args.port);
    
    join_network(&program_args);
    listen_for_messages();
    
    g_close_socket();
    return 0;
}