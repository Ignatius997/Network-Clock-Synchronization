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

#define MSG_HELLO           1
#define MSG_HELLO_REPLY     2
#define MSG_CONNECT         3
#define MSG_ACK_CONNECT     4
#define MSG_SYNC_START      11
#define MSG_DELAY_REQUEST   12
#define MSG_DELAY_RESPONSE  13
#define MSG_LEADER          21
#define MSG_GET_TIME        31
#define MSG_TIME            32

#define IPV4_ADDR_LEN 4

#define MAX_DATA 65535 // TODO lepsza nazwa

// TODO: Skopiować mimową bibliotekę errorową. Czy można?
void syserr(const char *msg) {
    fprintf(stderr, "%s\n", msg);
    exit(1);
}

typedef struct __attribute__((__packed__)) {
    uint8_t     peer_address_length;
    uint8_t     peer_address[16];
    uint16_t    peer_port;
} Peer;

Peer peer_init() {
    Peer p;
    memset(&p, 0, sizeof(Peer));
    return p;
}

void peer_print(Peer *p) {
    fprintf(stderr, "Peer %p:\n", (void*) p);
    fprintf(stderr, "  Address Length: %u\n", p->peer_address_length);
    fprintf(stderr, "  Address: ");
    for (uint8_t i = 0; i < p->peer_address_length; ++i) {
        fprintf(stderr, "%s%u", (i > 0 ? "." : ""), p->peer_address[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "  Port: %u\n", p->peer_port);
}

void peer_convert_to_network(Peer *p) {
    p->peer_port = htons(p->peer_port);
}

void peer_convert_to_host(Peer *p) {
    p->peer_port = ntohs(p->peer_port);
}

/** Node attributes shall be accessible via global variables.
 * Naming convention: g_{name}.
 */
static int      g_socket_fd;
static Peer*    g_peers; // Known peer nodes.
static uint16_t g_count; // Number of known peer nodes
static uint16_t g_peers_capacity; // `g_peers` capacity

void peer_add(Peer *p) {
    if (g_count == UINT16_MAX) {
        syserr("Too many peers"); // TODO czy może coś innego zrobić.
    }

    if (g_count + 1 == g_peers_capacity) {
        g_peers_capacity = g_peers_capacity << 1; 
        g_peers = (Peer *) realloc(g_peers, g_peers_capacity * sizeof(Peer));
        if (g_peers == NULL) syserr("realloc");
    }

    g_peers[g_count++] = *p;
}

void init_global() {
    g_count = 0;
    g_peers_capacity = 1;
    g_peers = (Peer*) malloc(g_peers_capacity * sizeof(Peer));
    if (g_peers == NULL) syserr("malloc g_peers");
    // TODO sprawdź, czy alokacja się powiodła
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
static struct sockaddr_in get_peer_address(char const *peer_ip_str, uint16_t port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    struct addrinfo *address_result;
    int errcode = getaddrinfo(peer_ip_str, NULL, &hints, &address_result);
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
    if ((argc-1) % 2 == 1) syserr("Incorrect arguments: odd number..."); // TODO Better message. But should we even consider it an error?
    
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
    uint8_t     peer_address[16]; // node IP address
    uint16_t    peer_port;
    uint64_t    timestamp;
    uint8_t     synchronized;
} Message;

void msg_print(const Message *msg) {
    fprintf(stderr, "Message %p:\n", (void*) msg);
    fprintf(stderr, "  Type: %u\n", msg->message);
    fprintf(stderr, "  Count: %u\n", msg->count);
    fprintf(stderr, "  Peer Address Length: %u\n", msg->peer_address_length);
    fprintf(stderr, "  Peer Address: ");
    for (uint8_t i = 0; i < msg->peer_address_length; ++i) {
        fprintf(stderr, "%s%u", (i > 0 ? "." : ""), msg->peer_address[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "  Peer Port: %u\n", msg->peer_port);
    fprintf(stderr, "  Timestamp: %" PRIu64 "\n", msg->timestamp);
    fprintf(stderr, "  Synchronized: %u\n", msg->synchronized);
}

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

Message msg_hello_reply() {
    Message msg = msg_init();
    msg.message = MSG_HELLO_REPLY;
    msg.count = g_count;
    return msg;
}

inline Message msg_connect() {
    Message msg = msg_init();
    msg.message = MSG_CONNECT;
    return msg;
}

inline Message msg_acknowledge_connection() {
    Message msg = msg_init();
    msg.message = MSG_ACK_CONNECT;
    return msg;
}

// TODO te całe wysyłanie możnaby jakoś ujednolicić.
// TODO dodać to cale oczekiwanie od 5 do 10 sekund

int msg_send(Message *msg, const struct sockaddr_in *peer_address) {
    msg_convert_to_network(msg);
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    return sendto(g_socket_fd, msg, sizeof(*msg), 0,
                  (struct sockaddr *) peer_address, addr_len);
}

void notify_peer(struct sockaddr_in *peer_address) {
    Message msg = msg_hello();
    ssize_t send_len = msg_send(&msg, peer_address);
    if (send_len < 0) syserr("sendto HELLO");
}

// TODO czy mozna sensownie ujednolicic wysylanie, aby to tez mozna bylo dac do funkcji `msg_send`?
void reply(struct sockaddr_in *peer_address) {
    Message msg = msg_hello_reply();
    msg_convert_to_network(&msg);

    size_t msg_size = sizeof(Message);
    size_t peers_size = g_count * sizeof(Peer);
    size_t total_size = msg_size + peers_size;

    uint8_t *buf = (uint8_t*) malloc(total_size);
    if (buf == NULL) syserr("malloc");

    memcpy(buf, &msg, msg_size);
    memcpy(buf + msg_size, g_peers, peers_size);
    
    size_t offset = sizeof(Message);
    for (size_t i = 0; i < g_count; ++i) {
        Peer *p = (Peer *) (buf + offset);
        p->peer_port = htons(p->peer_port);
        offset += sizeof(Peer);
    }

    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    ssize_t send_len = sendto(g_socket_fd, buf, total_size, 0,
                              (struct sockaddr *) peer_address, addr_len);
    if (send_len < 0) syserr("sendto HELLO REPLY");
    
    fprintf(stderr, "Sent HELLO_REPLY message (%zd bytes)\n", send_len);
    msg_print(&msg);
    free(buf);
}

uint8_t receive_reply(struct sockaddr_in *peer_address, Peer **peers) {
    uint8_t buf[MAX_DATA];
    Message msg;
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);

    // Receive HELLO REPLY message.
    ssize_t recv_len = recvfrom(g_socket_fd, buf, sizeof(buf), 0,
                                (struct sockaddr *) peer_address, &addr_len);
    if (recv_len < 0) syserr("recvfrom HELLO_REPLY");

    // Deserialize Message structure.
    memcpy(&msg, buf, sizeof(Message));
    msg_convert_to_host(&msg);
    if (msg.message != MSG_HELLO_REPLY) syserr("Received not reply? WTH?");
    fprintf(stderr, "Received HELLO_REPLY message (%zd bytes)\n", recv_len);

    // Copy contents of peers
    if (msg.count > 0) {
        *peers = malloc(msg.count * sizeof(Peer));
        if (*peers == NULL) syserr("malloc failed");
        memcpy(*peers, buf + sizeof(Message), msg.count);

        fprintf(stderr, "Peers from HELLO_REPLY:\n");
        for (size_t i = 0; i < msg.count; ++i) {
            peer_convert_to_host(&(*peers)[i]);
            peer_print(&(*peers)[i]);
        }
    }

    return msg.count;
}

void send_connect(struct sockaddr_in *peer_address) {
    Message msg = msg_connect();
    ssize_t send_len = msg_send(&msg, peer_address);
    if (send_len < 0) syserr("sendto CONNECT");
    fprintf(stderr, "Sent CONNECT message (%zd bytes)\n", send_len);
}

void acknowledge_connection(struct sockaddr_in *peer_address) {
    Message msg = msg_acknowledge_connection();
    ssize_t send_len = msg_send(&msg, peer_address);
    if (send_len < 0) syserr("sendto ACK CONNECT");
    fprintf(stderr, "Sent ACK_CONNECT message (%zd bytes)\n", send_len);
}

// TODO lepsza nazwa
void _connect(Peer *p) {
    if (p->peer_address_length != IPV4_ADDR_LEN) syserr("Wrong address");

    // TODO nie da sie sprytniej?
    char peer_ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, (struct in_addr *)p->peer_address, peer_ip_str, INET_ADDRSTRLEN) == NULL) {
        syserr("inet_ntop failed");
    }

    struct sockaddr_in peer_address = get_peer_address(peer_ip_str, p->peer_port);
    send_connect(&peer_address);
}

// TODO Lepsza nazwa
void ack_connect() {
    uint8_t buf[MAX_DATA + sizeof(Message)]; // TODO dziadostwo
    Message msg;
    struct sockaddr_in peer_address;
    memset(&peer_address, 0, sizeof(peer_address)); // TODO potrzebne?
    socklen_t addr_len = (socklen_t) sizeof(peer_address);

    // Receive HELLO REPLY message.
    ssize_t recv_len = recvfrom(g_socket_fd, buf, sizeof(buf), 0,
                                (struct sockaddr *) &peer_address, &addr_len);
    if (recv_len < 0) syserr("recvfrom ACK_CONNECT");
    if (recv_len < (ssize_t) sizeof(Message)) {
        syserr("Received message too small for Message structure");
    }

    uint8_t ip[16];
    memset(ip, 0, sizeof(ip));
    memcpy(ip, &peer_address.sin_addr, IPV4_ADDR_LEN);
    uint16_t port = ntohs(peer_address.sin_port);

    // Deserialize Message structure.
    memcpy(&msg, buf, sizeof(Message));
    msg_convert_to_host(&msg);
    if (msg.message != MSG_HELLO_REPLY) syserr("Received not ACK_CONNECT!");

    // TODO czy tutaj trzeba tworzyć nowego Peera?
    Peer *p = (Peer *)malloc(sizeof(Peer));
    if (p == NULL) syserr("malloc peer");

    p->peer_address_length = IPV4_ADDR_LEN;
    memcpy(p->peer_address, ip, IPV4_ADDR_LEN);
    p->peer_port = port;
    
    peer_add(p);
    free(p);
}

void join_network(ProgramArgs args) {
    if (!args._ar_provided) return;

    struct sockaddr_in peer_address = get_peer_address(args.peer_address, args.peer_port);
    Peer *peers = NULL;

    notify_peer(&peer_address);
    uint8_t count = receive_reply(&peer_address, &peers);

    for (uint8_t i = 0; i < count; ++i) {
        _connect(&peers[i]);
    }

    for (uint8_t i = 0; i < count; ++i) {
        ack_connect();
    }

    free(peers);
}

// TODO Daj w inne miejsce
void validate_address(const struct sockaddr_in *addr) {
    if (addr->sin_family != AF_INET) {
        syserr("Invalid address family");
    }

    // TODO Should we check it?
    // if (addr->sin_port == 0) {
    //     syserr("Port number is zero");
    // }
    
    // if (addr->sin_addr.s_addr == INADDR_NONE) {
    //     syserr("Invalid IP address");
    // }
}

void listen_for_messages() {
    uint8_t buf[MAX_DATA]; // TODO uint8_t czy char?
    memset(buf, 0, sizeof(buf));

    struct sockaddr_in peer_address;

    while (true) {
        socklen_t addr_len = (socklen_t) sizeof(peer_address);

        // Odbiór danych
        ssize_t recv_len = recvfrom(g_socket_fd, buf, sizeof(buf), 0,
                                    (struct sockaddr *) &peer_address, &addr_len);
        if (recv_len < 0) {
            perror("recvfrom failed");
            continue;
        }

        if (recv_len < (ssize_t) sizeof(Message)) {
            syserr("recvfrom less bytes than message size."); // TODO czy na pewno to zawsze błąd?
        }

        // Interpretacja odebranych danych jako struktura Message
        Message msg;
        memcpy(&msg, buf, sizeof(Message));
        msg_convert_to_host(&msg);

        // Validate peer_address contents.
        validate_address(&peer_address);

        // Sprawdzenie typu komunikatu
        switch (msg.message) {
            case MSG_HELLO:
                reply(&peer_address);
                break;

            // case MSG_HELLO_REPLY:
            //     handle_hello_reply(msg->data, received_length - sizeof(Message));
            //     break;

            default: // Nieznany typ komunikatu
                printf("Unknown message type: %d\n", msg.message);
                break;
        }
    }
}

int main(int argc, char* argv[]) {
    init_global();

    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    init_socket(&bind_address, program_args.bind_address, program_args.port);
    
    join_network(program_args);
    listen_for_messages();
    
    close(g_socket_fd);
    return 0;
}