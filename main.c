#include <stdint.h>
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

// TODO: Skopiować mimową bibliotekę errorową. Czy można?
void syserr(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
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

uint8_t get_ip_length(const char* address) {
    struct in_addr ipv4_addr;
    struct in6_addr ipv6_addr;
    uint8_t len;

    if (inet_pton(AF_INET, address, &ipv4_addr) == 1) {
        len = 8;
    } else if (inet_pton(AF_INET6, address, &ipv6_addr) == 1) {
        len = 16;
    } else {
        syserr("Niepoprawny adres ip");
    }

    return len;
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
typedef struct Message {
    // TODO Czy na pewno `uint`, a nie `int` w niektórych polach?
    uint8_t     message; // message type
    uint16_t    count; // count of known nodes
    uint8_t     peer_address_length; // number of octets in `peer_address`
    uint8_t     *peer_address; // node IP address
    uint16_t    peer_port;
    uint64_t    timestamp;
    uint8_t     synchronized;
} Message;

Message msg_init() {
    Message msg;
    memset(&msg, 0, sizeof(Message));
    return msg;
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

void notify_peer(ProgramArgs args) {
    Message msg_hello = msg_hello();
    // Wyślij hello
    struct sockadr_in peer_address = get_peer_address(args.peer_address, args.peer_port);
    char const *peer_ip = inet_ntoa(peer_address.sin_addr);
    uint16_t peer_port = ntohs(peer_address.sin_port);
    connect_

    // Odbierz komunikat HELLO_REPLY
    for (address in reply.peer_address) {
        connect with address:reply.peer_port; // with msg_connect
    }
    // Czy to można rzeczywiście rozbić na dwie pętle?
    for (address in reply.peer_address) {
        receive msg_ack_connect;
        dodaj do listy wezlow potwierdzony wezel;
    }
}

// TODO przenieść w inne miejsce
void init_addr(struct sockaddr_in *bind_address, uint16_t port) {
    // NOTE kod i komentarz zajumany z echo-server.c z labów udp.
    // Bind the socket to a concrete address
    bind_address->sin_family = AF_INET; // IPv4
    bind_address->sin_addr.s_addr = htonl(INADDR_ANY);
    bind_address->sin_addr = htons(port);
}

// TODO przenieść w inne miejsce
// TODO lepsza nazwa
// TODO rozbić socket z bind_address?
void init_socket(struct sockaddr_in *bind_address, uint16_t port) {
    g_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_socket_fd < 0) {
        syserr("Socket creation failed");
    }

    init_addr(bind_address, port);

    if (bind(g_socket_fd, (struct sockaddr *) bind_address, (socklen_t) sizeof(*bind_address)) < 0) {
        syserr("bind");
    }

    fprintf(stderr, "Listening on port %" PRIu16 "\n", port);
}

void join_network(ProgramArgs args) {
    if (args._ar_provided) {
        notify_peer(args);
    } else {
        // Nasłuchuj komunikatów.
    }
}

int main(int argc, char* argv[]) {
    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    init_socket(&bind_address, program_args.port);
    
    join_network(program_args);
    
    return 0;
}