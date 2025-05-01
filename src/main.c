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

#include "../include/peer.h"
#include "../include/netutil.h"
#include "../include/err.h"
#include "../include/args.h"
#include "../include/sigman.h"
#include "../include/message.h"
#include "../include/loglib.h"
#include "../include/nethandle.h"
#include "../include/netrecv.h"
#include "../include/netsend.h"

#define IPV4_ADDR_LEN 4

#define BUF_SIZE 65535 // FIXME myślę, że więcej

/** Node attributes shall be accessible via global variables.
 * Naming convention: g_{name}.
 */
int      g_socket_fd; // ofc host order
uint8_t  g_buf[BUF_SIZE]; // Buffer for read operations.

// TODO te całe wysyłanie możnaby jakoś ujednolicić.
// TODO dodać to cale oczekiwanie od 5 do 10 sekund

ssize_t receive_message(struct sockaddr_in *peer_address) {
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    ssize_t recv_len = recvfrom(g_socket_fd, g_buf, sizeof(g_buf), 0,
                                (struct sockaddr *) peer_address, &addr_len);
    int val = nutil_validate_received_data(peer_address, g_buf, recv_len);
    (void)val; // NOTE nieużyta zmienna

    return recv_len;
}

void join_network(const ProgramArgs *args) {
    if (!args->_ar_provided) return;

    struct sockaddr_in peer_address;
    nutil_set_address(args->peer_address, htons(args->peer_port), &peer_address);
    
    Peer first;
    first.peer_address_length = 4 /*FIXME IPV4_ADDR_LEN*/;
    if (inet_pton(AF_INET, args->peer_address, first.peer_address) != 1) {
        syserr("inet_pton failed");
    }
    first.peer_port = htons(args->peer_port);
    peer_add(&first);

    // FIXME No to jest tragedia, że trzeba recznie ustawiać sinfo. Ale cóż ...
    SendInfo sinfo = {
        .buf = g_buf,
        .len = -1,
        .peer_address = peer_address,
    };
    nsend_hello(&sinfo);
}

void listen_for_messages() {
    struct sockaddr_in peer_address;

    while (true) {
        ssize_t recv_len = receive_message(&peer_address);
        nhandle_message(&peer_address, g_buf, recv_len);
    }
}

int main(int argc, char* argv[]) {
    memset(g_buf, 0, BUF_SIZE);
    sig_setup_signal_handler(); // Just for debugging I guess.

    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);
    args_print(&program_args);
    args_validate(&program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    nutil_init_socket(&g_socket_fd, &bind_address, program_args.bind_address, program_args.port);
    nsend_set_socket_fd(g_socket_fd); // XD, ta linijka właśnie pokazuje, jak głupi jest static socket_fd
    
    join_network(&program_args);
    listen_for_messages();
    
    cmn_close_socket(g_socket_fd);
    return 0;
}