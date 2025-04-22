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

#define DEFAULT_PORT 0

#define ARGOPT_BIND_ADDRESS 'b'
#define ARGOPT_PORT         'p'
#define ARGOPT_PEER_ADDRESS 'a'
#define ARGOPT_PEER_PORT    'r'

#define MSG_HELLO       1
#define MSG_HELLO_REPLY 2
#define MSG_CONNECT     3
#define MSG_ACK_CONNECT 4

#define MSG_SYNC_START     11
#define MSG_DELAY_REQUEST  12
#define MSG_DELAY_RESPONSE 13

#define MSG_LEADER 21

#define MSG_GET_TIME 31
#define MSG_TIME     32

/** Node attributes shall be accessible via global variables.
 * Naming convention: g_{name}.
 */
static int g_socket_fd;

// TODO: Skopiować mimową bibliotekę errorową. Czy można?
void syserr(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

uint32_t get_address(const char *addr) {
    uint32_t inaddr = addr == NULL ? htonl(INADDR_ANY) : inet_addr(addr);
    if (inaddr == INADDR_NONE && addr != NULL) {
        syserr("Invalid IPv4 address");
    }
    return inaddr;
}

// TODO przenieść w inne miejsce
void init_addr(struct sockaddr_in *bind_address, const char *addr, const uint16_t port) {
    // NOTE kod i komentarz zajumany z echo-server.c z labów udp.
    // Bind the socket to a concrete address
    bind_address->sin_family = AF_INET; // IPv4
    bind_address->sin_addr.s_addr = get_address(addr);
    bind_address->sin_port = htons(port);
}

// TODO obsłużyć przypadek bez podanego portu
// TODO przenieść w inne miejsce
// TODO lepsza nazwa
// TODO rozbić socket z bind_address?
void init_socket(struct sockaddr_in *bind_address, const char *addr, const uint16_t port) {
    g_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_socket_fd < 0) {
        syserr("Socket creation failed");
    }

    init_addr(bind_address, addr, port);

    if (bind(g_socket_fd, (struct sockaddr *) bind_address, (socklen_t) sizeof(*bind_address)) < 0) {
        syserr("bind");
    }

    fprintf(stderr, "Listening on port %" PRIu16 "\n", port);
}

// TODO przeniesc w inne miejsce
/**
 * Zajumane z labów udp: funkcja `get_server_address`.
 */
static struct sockaddr_in get_peer_address(char const *peer, uint16_t port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    int errcode = getaddrinfo(peer, NULL, &hints, &address_result);
    if (errcode != 0) {
        syserr("getaddrinfo"); // OG: `fatal("getaddrinfo: %s", gai_strerror(errcode));`
    }

    struct sockaddr_in send_address;
    send_address.sin_family = AF_INET;  // IPv4
    send_address.sin_addr.s_addr =      // IP address
        ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr;
    send_address.sin_port = htons(port);

    freeaddrinfo(address_result);
    return send_address;
}

// ---- Program arguments parsing ---- //

typedef struct ProgramArgs {
    char        *bind_address;
    uint16_t    port;
    char        *peer_address;
    uint16_t    peer_port;
    
    bool        _ar_provided;
} ProgramArgs;

ProgramArgs args_default() {
    return (ProgramArgs) {
        .bind_address   = NULL,
        .port           = DEFAULT_PORT,
        .peer_address   = NULL,
        .peer_port      = DEFAULT_PORT,
    
        ._ar_provided           = false,
    };
}

regex_t argument_option_regex(void) {
    const char *pattern = "^-[bpar]$";
    regex_t regex;
    
    if (regcomp(&regex, pattern, REG_EXTENDED) != 0)
        syserr("Regex compilation failed!");

    return regex;
}

/**
 * "Ukradzione" z kodu z laboratoriów.
 */
uint16_t read_port(char const *string) {
    char *endptr;
    errno = 0;
    unsigned long port = strtoul(string, &endptr, 10);
    
    if (errno != 0 || *endptr != 0 || port == 0 || port > UINT16_MAX) {
        syserr("Given port is not a valid port number"); // FIXME w oryginalne `fatal`.
        // OG: fatal("%s is not a valid port number", string);
    }

    return (uint16_t) port;
}

// TODO Komentarz.
void args_load_value(char *arg, const char opt, ProgramArgs *program_args) {
    switch (opt) {
        case ARGOPT_BIND_ADDRESS:
            program_args->bind_address = arg;
            break;

        case ARGOPT_PORT:
            program_args->port = read_port(arg);
            break;

        case ARGOPT_PEER_ADDRESS:
            program_args->peer_address = arg;
            break;

        case ARGOPT_PEER_PORT:
            program_args->peer_port = read_port(arg);
            break;

        default:
            syserr("ERROR Regex or switch case failed"); // TODO lepszy komunikat.
    }
}

// TODO Komentarz.
void args_parse(int argc, char* argv[], ProgramArgs *program_args) {
    if (argc-1 % 2 == 1) syserr("Incorrect arguments: odd number..."); // TODO Better message. But should we even consider it an error?
    
    regex_t argopt_regex = argument_option_regex();

    // FIXME: Ewentualnie można zamienić na sprawdzanie parzystości i.
    bool option = true; // Tells, whether a flag an option, i.e. "-b" is required.
    char opt;
    // int ar = 0; // TODO Lepsza nazwa.ń
    bool a_provided = false, r_provided = false;

    for (int i = 1; i < argc; ++i) {
        if (option) {
            if (regexec(&argopt_regex, argv[i], 0, NULL, 0) != 0) {
                syserr("Wrong parameters!"); // TODO Print usage.
            } else {
                opt = argv[i][1];
            }
        } else {
            args_load_value(argv[i], opt, program_args);
            if (opt == ARGOPT_PEER_ADDRESS) {
                a_provided = true;
            } else if (opt == ARGOPT_PEER_PORT) {
                r_provided = true;
            }
        }

        option = !option;
    }

    regfree(&argopt_regex);
    if (a_provided == r_provided) {
        program_args->_ar_provided = a_provided;
    } else {
        syserr("-a and -r not provided both."); // TODO Better message.
    }
}

// TODO komentarz.
/**
 * Passed by pointer to print accurate address.
 */
void args_print(ProgramArgs *args) {
    fprintf(stderr, "ProgramArgs %p:\n", (void*) args);
    fprintf(stderr, "  Bind Address: %s\n", args->bind_address ? args->bind_address : "NULL");
    fprintf(stderr, "  Port: %u\n", args->port);
    fprintf(stderr, "  Peer Address: %s\n", args->peer_address ? args->peer_address : "NULL");
    fprintf(stderr, "  Peer Port: %u\n", args->peer_port);
}

// TODO lepsza nazwa: ---- Node Message Struct ---- //

// TODO komentarz
typedef struct __attribute__((__packed__)) {
    uint8_t     message; // message type
    uint16_t    count; // count of known nodes
    uint8_t     peer_address_length; // number of octets in `peer_address`
    uint8_t     *peer_address; // node IP address
    uint16_t    peer_port;
    uint64_t    timestamp;
    uint8_t     synchronized;
} Message;

// FIXME PRIORYTET 1: O CO CHODZI Z TRZECIM I CZWARTYM POLEM?

Message msg_init() {
    Message msg;
    memset(&msg, 0, sizeof(Message));
    return msg;
}

void msg_convert_to_network(Message *msg) {
    msg->count = htons(msg->count);
    msg->peer_port = htons(msg->peer_port);
    msg->timestamp = htobe64(msg->timestamp);
}

void msg_convert_to_host(Message *msg) {
    msg->count = ntohs(msg->count);
    msg->peer_port = ntohs(msg->peer_port);
    msg->timestamp = be64toh(msg->timestamp);
}

Message msg_hello() {
    Message msg = msg_init();
    msg.message = MSG_HELLO;
    return msg;
}

inline Message msg_hello_reply() {

}

inline Message msg_connect() {

}

inline Message msg_acknowledge_connect() {

}

void notify_peer(struct sockaddr_in *peer_address) {
    Message msg = msg_hello();
    msg_convert_to_network(&msg);
    
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);

    ssize_t send_len = sendto(g_socket_fd, &msg, sizeof(msg), 0,
                          (struct sockaddr *) peer_address, addr_len);
    if (send_len < 0) syserr("sendto HELLO");
}

void receive_reply(struct sockaddr_in *peer_address) {
    Message msg;
    socklen_t addr_len;

    ssize_t recv_len = recvfrom(g_socket_fd, &msg, sizeof(msg), 0,
                                (struct sockaddr *) peer_address, &addr_len);
    if (recv_len < 0) syserr("recvfrom HELLO_REPLY");
    msg_convert_to_host(&msg);

    if (msg.message != MSG_HELLO_REPLY) syserr("Received not reply? WTH?");
}

void join_network(ProgramArgs args) {
    if (args._ar_provided) {
        struct sockaddr_in peer_address = get_peer_address(args.peer_address, args.peer_port);
        
        notify_peer(&peer_address);
        receive_reply(&peer_address);

        // TODO
        // for (address in reply.peer_address) {
        //     connect with address:reply.peer_port; // with msg_connect
        // }
    
        // for (address in reply.peer_address) {
        //     receive msg_ack_connect;
        //     dodaj do listy wezlow potwierdzony wezel;
        // }
    } else {
        // Nasłuchuj komunikatów.
    }
}

void listen_for_messages() {
    struct sockaddr_in sender_address;
    socklen_t addr_len = sizeof(sender_address);
    Message msg;

    while (true) {
        ssize_t recv_len = recvfrom(g_socket_fd, &msg, sizeof(msg), 0,
                                    (struct sockaddr *) &sender_address, &addr_len);
        if (recv_len < 0) {
            syserr("recvfrom failed");
        }

        msg_convert_to_host(&msg);

        switch (msg.message) {
            case MSG_HELLO:
                fprintf(stderr, "Received HELLO message\n");
                // Handle HELLO message
                break;

            case MSG_HELLO_REPLY:
                fprintf(stderr, "Received HELLO_REPLY message\n");
                // Handle HELLO_REPLY message
                break;

            case MSG_CONNECT:
                fprintf(stderr, "Received CONNECT message\n");
                // Handle CONNECT message
                break;

            case MSG_ACK_CONNECT:
                fprintf(stderr, "Received ACK_CONNECT message\n");
                // Handle ACK_CONNECT message
                break;

            default:
                fprintf(stderr, "Unknown message type: %u\n", msg.message);
                break;
        }
    }
}

int main(int argc, char* argv[]) {
    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    init_socket(&bind_address, program_args.bind_address, program_args.port);
    
    join_network(program_args);
    listen_for_messages();
    
    close(g_socket_fd);
    return 0;
}