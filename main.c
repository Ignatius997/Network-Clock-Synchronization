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
#define MSG_MAX       255

#define BUF_SIZE 65535 // FIXME myślę, że więcej

void close_socket(void);

// TODO: Skopiować mimową bibliotekę errorową. Czy można?
void syserr(const char *msg) {
    fprintf(stderr, "%s, closing socket and exiting...\n", msg);
    close_socket();
    exit(1);
}

typedef struct __attribute__((__packed__)) {
    uint8_t     peer_address_length;
    uint8_t     peer_address[16];
    uint16_t    peer_port; // trzymane zawsze w big endianess
} Peer;

Peer peer_init(void) {
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
    fprintf(stderr, "  Port: %u\n", ntohs(p->peer_port));
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
// NOTE tutaj trzymamy wszystko w host, czyli, w little endianness.
static int      g_socket_fd; // ofc host order
static Peer*    g_peers; // Known peer nodes (fields in g_peers are in big endianess).
static uint16_t g_count; // Number of known peer nodes in host order
static uint16_t g_peers_capacity; // `g_peers` capacity in host order
static uint8_t  g_buf[BUF_SIZE] = {0}; // Buffer for read operations.

/** Auxiliary */
void close_socket(void) {
    if (g_socket_fd >= 0) {
        close(g_socket_fd);
        fprintf(stderr, "Socket closed.\n");
    }
}

/** Auxiliary */
void handle_sigint(int sig) {
    fprintf(stderr, "\nCaught signal %d (SIGINT). Closing socket and exiting...\n", sig);
    close_socket();
    exit(130);
}

void handle_quit(int sig) {
    fprintf(stderr, "\nCaught signal %d (EOF). Printing all peers:\n", sig);
    for (uint16_t i = 0; i < g_count; ++i) {
        peer_print(&g_peers[i]);
    }
    fprintf(stderr, "\n");
}

/** Auxiliary */
void setup_signal_handler() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    // Obsługa SIGINT
    sa.sa_handler = handle_sigint;
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        syserr("sigaction failed for SIGINT");
    }

    // Obsługa SIGQUIT (EOF)
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_quit;
    if (sigaction(SIGQUIT, &sa, NULL) < 0) {
        syserr("sigaction failed for SIGQUIT");
    }
}

void peer_add(const Peer *p) {
    if (g_count == UINT16_MAX) {
        syserr("Too many peers"); // TODO czy może coś innego zrobić.
    }

    if (g_count + 1 == g_peers_capacity) {
        g_peers_capacity = g_peers_capacity << 1; 
        g_peers = (Peer *) realloc(g_peers, g_peers_capacity * sizeof(Peer));
        if (g_peers == NULL) syserr("realloc");
    }

    memcpy(&g_peers[g_count++], p, sizeof(Peer));
}

/** O(g_count) */
Peer* peer_find(const struct sockaddr_in *peer_address) {
    uint16_t port = peer_address->sin_port;
    uint32_t addr = peer_address->sin_addr.s_addr;

    Peer *p = NULL;
    for (size_t i = 0; i < g_count; ++i) {
        if (g_peers[i].peer_port == port &&
            memcmp(g_peers[i].peer_address, &addr, IPV4_ADDR_LEN) == 0) {
            p = &g_peers[i];
            break;
        }
    }

    return p;
}


void init_global(void) {
    g_count = 0;
    g_peers_capacity = 1;
    g_peers = (Peer*) malloc(g_peers_capacity * sizeof(Peer));
    if (g_peers == NULL) syserr("malloc g_peers");
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

// TODO obsłużyć przypadek bez podanego portu (chyba obsluzony, bo port wtedy jest rowny 0)
// TODO przenieść w inne miejsce
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
struct sockaddr_in get_peer_address(char const *peer_ip_str, uint16_t port) {
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

void args_validate(const ProgramArgs *program_args) {
    (void)program_args;
    // TODO Implement
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

// ==== Node Message Struct ==== // Lepsza nazwa ofc

// NOTE Trzymamy wszystko w big endianess.
typedef struct __attribute__((__packed__)) {
    uint8_t  message; // message type
} Message;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} HelloMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint16_t count; // count of known nodes
} HelloReplyMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} ConnectMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} AckConnectMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
    uint64_t timestamp;
} SyncStartMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} DelayRequestMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
    uint64_t timestamp;
} DelayResponseMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
} LeaderMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
} GetTimeMessage;

typedef struct __attribute__((__packed__)) {
    Message  base; // Base Message
    uint8_t  synchronized;
    uint64_t timestamp;
} TimeMessage;

// NOTE Powinno być gdzie indziej
// NOTE Pakujemy, żeby ponad dwukrotnie zmniejszyć rozmiar struktury
typedef struct __attribute__((__packed__)) {
    uint8_t message;
    size_t  size;
    bool    allow_unknown_sender;
} MessageInfo;

/** Information about send operation. Packed to save memory. */
typedef struct __attribute__((__packed__)) {
    ssize_t send_len;
    bool    known; // Used in sending hello-reply message // NOTE zmienić nazwę
} SendInfo;

static MessageInfo g_msg_info[MSG_MAX+1];

void _set_msg_info_size(void) {
    g_msg_info[MSG_HELLO].size          = sizeof(HelloMessage);
    g_msg_info[MSG_HELLO_REPLY].size    = sizeof(HelloReplyMessage);
    g_msg_info[MSG_CONNECT].size        = sizeof(ConnectMessage);
    g_msg_info[MSG_ACK_CONNECT].size    = sizeof(AckConnectMessage);
    g_msg_info[MSG_SYNC_START].size     = sizeof(SyncStartMessage);
    g_msg_info[MSG_DELAY_REQUEST].size  = sizeof(DelayRequestMessage);
    g_msg_info[MSG_DELAY_RESPONSE].size = sizeof(DelayResponseMessage);
    g_msg_info[MSG_LEADER].size         = sizeof(LeaderMessage);
    g_msg_info[MSG_GET_TIME].size       = sizeof(GetTimeMessage);
    g_msg_info[MSG_TIME].size           = sizeof(TimeMessage);
}

void _set_msg_info_allow_unknown_sender(void) {
    g_msg_info[MSG_HELLO].allow_unknown_sender          = true;
    g_msg_info[MSG_HELLO_REPLY].allow_unknown_sender    = true;
    g_msg_info[MSG_CONNECT].allow_unknown_sender        = true;
    g_msg_info[MSG_ACK_CONNECT].allow_unknown_sender    = true;
    g_msg_info[MSG_SYNC_START].allow_unknown_sender     = false;
    g_msg_info[MSG_DELAY_REQUEST].allow_unknown_sender  = false;
    g_msg_info[MSG_DELAY_RESPONSE].allow_unknown_sender = false;
    g_msg_info[MSG_LEADER].allow_unknown_sender         = true;
    g_msg_info[MSG_GET_TIME].allow_unknown_sender       = true;
    g_msg_info[MSG_TIME].allow_unknown_sender           = true;
}

void init_msg_info(void) {
    memset(g_msg_info, 0, sizeof(g_msg_info));
    _set_msg_info_size();
    _set_msg_info_allow_unknown_sender();
}

// TODO można skrócić
void msg_print(const Message *msg) {
    fprintf(stderr, "Message %p:\n", (void*) msg);
    switch (msg->message) {
        case MSG_HELLO:
            fprintf(stderr, "  Type: HELLO\n");
            break;

        case MSG_HELLO_REPLY:
            HelloReplyMessage *hello_reply = (HelloReplyMessage *) msg;
            fprintf(stderr, "  Type: HELLO_REPLY\n");
            fprintf(stderr, "  Count: %u\n", ntohs(hello_reply->count));
            break;

        case MSG_CONNECT:
            fprintf(stderr, "  Type: CONNECT\n");
            break;

        case MSG_ACK_CONNECT:
            fprintf(stderr, "  Type: ACK_CONNECT\n");
            break;

        case MSG_SYNC_START:
            SyncStartMessage *sync_start = (SyncStartMessage *) msg;
            fprintf(stderr, "  Type: SYNC_START\n");
            fprintf(stderr, "  Timestamp: %" PRIu64 "\n", be64toh(sync_start->timestamp));
            fprintf(stderr, "  Synchronized: %u\n", sync_start->synchronized);
            break;

        case MSG_DELAY_REQUEST:
            fprintf(stderr, "  Type: DELAY_REQUEST\n");
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseMessage *delay_response = (DelayResponseMessage *) msg;
            fprintf(stderr, "  Type: DELAY_RESPONSE\n");
            fprintf(stderr, "  Synchronized: %u\n", delay_response->synchronized);
            fprintf(stderr, "  Timestamp: %" PRIu64 "\n", be64toh(delay_response->timestamp));
            break;

        case MSG_LEADER:
            LeaderMessage *leader = (LeaderMessage *) msg;
            fprintf(stderr, "  Type: LEADER\n");
            fprintf(stderr, "  Synchronized: %u\n", leader->synchronized);
            break;

        case MSG_GET_TIME:
            fprintf(stderr, "  Type: GET_TIME\n");
            break;

        case MSG_TIME:
            TimeMessage *time_msg = (TimeMessage *) msg;
            fprintf(stderr, "  Type: TIME\n");
            fprintf(stderr, "  Synchronized: %u\n", time_msg->synchronized);
            fprintf(stderr, "  Timestamp: %" PRIu64 "\n", be64toh(time_msg->timestamp));
            break;

        default:
            fprintf(stderr, "  Unknown message type: %u\n", msg->message);
            break;
    }
}

void msg_convert_to_network(Message *msg) {
    switch (msg->message) {
        case MSG_HELLO_REPLY:
            HelloReplyMessage *hello_reply = (HelloReplyMessage *)(void *)msg;
            hello_reply->count = htons(hello_reply->count);
            break;

        case MSG_SYNC_START:
            SyncStartMessage *sync_start = (SyncStartMessage *)(void *)msg;
            sync_start->timestamp = htobe64(sync_start->timestamp);
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseMessage *delay_response = (DelayResponseMessage *)(void *)msg;
            delay_response->timestamp = htobe64(delay_response->timestamp);
            break;

        case MSG_TIME:
            TimeMessage *time_msg = (TimeMessage *)(void *)msg;
            time_msg->timestamp = htobe64(time_msg->timestamp);
            break;

        default:
            break;
    }
}

void msg_convert_to_host(Message *msg) {
    switch (msg->message) {
        case MSG_HELLO_REPLY:
            HelloReplyMessage *hello_reply = (HelloReplyMessage *)(void *)msg;
            hello_reply->count = ntohs(hello_reply->count);
            break;

        case MSG_SYNC_START:
            SyncStartMessage *sync_start = (SyncStartMessage *)(void *)msg;
            sync_start->timestamp = be64toh(sync_start->timestamp);
            break;

        case MSG_DELAY_RESPONSE:
            DelayResponseMessage *delay_response = (DelayResponseMessage *)(void *)msg;
            delay_response->timestamp = be64toh(delay_response->timestamp);
            break;

        case MSG_TIME:
            TimeMessage *time_msg = (TimeMessage *)(void *)msg;
            time_msg->timestamp = be64toh(time_msg->timestamp);
            break;

        default:
            break;
    }
}

size_t msg_size(const Message *msg) {
    return g_msg_info[msg->message].size;
}

// TODO te całe wysyłanie możnaby jakoś ujednolicić.
// TODO dodać to cale oczekiwanie od 5 do 10 sekund

const char* get_log(const Message *msg) {
    switch (msg->message) {
        case MSG_HELLO:
            return "MSG_HELLO";

        case MSG_HELLO_REPLY:
            return "MSG_HELLO_REPLY";

        case MSG_CONNECT:
            return "MSG_CONNECT";

        case MSG_ACK_CONNECT:
            return "MSG_ACK_CONNECT";

        case MSG_SYNC_START:
            return "MSG_SYNC_START";

        case MSG_DELAY_REQUEST:
            return "MSG_DELAY_REQUEST";

        case MSG_DELAY_RESPONSE:
            return "MSG_DELAY_RESPONSE";

        case MSG_LEADER:
            return "MSG_LEADER";

        case MSG_GET_TIME:
            return "MSG_GET_TIME";

        case MSG_TIME:
            return "MSG_TIME";

        default:
            return "UNKNOWN";
    }
}

// NOTE nie wiedziałem gdzie to dać
void log_received_message(const struct sockaddr_in *peer_address, const Message *msg, const ssize_t recv_len) {
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &peer_address->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
        syserr("inet_ntop failed");
    }

    const char *log = get_log(msg);
    fprintf(stderr, "Received %s message (%zd bytes) from %s:%u\n", log, recv_len, ip_str, ntohs(peer_address->sin_port));
    msg_print(msg);
    fprintf(stderr, "\n");
}

// NOTE nie wiedziałem gdzie to dać
void log_sent_message(const struct sockaddr_in *peer_address, const Message *msg, const ssize_t send_len) {
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &peer_address->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
        syserr("inet_ntop failed");
    }

    const char *log = get_log(msg);
    fprintf(stderr, "Sent %s message (%zd bytes) to %s:%u\n", log, send_len, ip_str, ntohs(peer_address->sin_port));
    msg_print(msg);
    fprintf(stderr, "\n");
}

void log_sending_peers(const Message *msg) {
    if (msg->message == MSG_HELLO_REPLY) {
        size_t offset = msg_size(msg);
        fprintf(stderr, "Sending peers:\n");
        for (size_t i = 0; i < ntohs(((HelloReplyMessage *)msg)->count); ++i) {
            Peer *p = (Peer *) (g_buf + offset);
            peer_print(p);
            offset += sizeof(Peer);
        }
    }
}

// NOTE Daj w inne miejsce
int validate_received_length(const ssize_t recv_len, const Message *msg) {
    // NOTE Program nie powinien się wywalać przy jednym złym receive, ale początkowo tak zróbmy dla świętego spokoju i debugowania
    
    if (recv_len < 0) {
        syserr("recvfrom failed");
    }

    if (recv_len < (ssize_t) msg_size(msg)) {
        syserr("recvfrom less bytes than message size."); // Można dodać rodzaj msg
        return 1;
    }

    return 0; // NOTE Na przyszłość (patrz linijka wyżej).
}

// NOTE Daj w inne miejsce
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

int validate_peers(const Message *msg) {
    if (msg->message == MSG_HELLO_REPLY) { // For extensibility.
        uint16_t peers_count = ntohs(((HelloReplyMessage *)msg)->count);
        
        if (peers_count > 0) {
            size_t offset = msg_size(msg);
            
            fprintf(stderr, "Validating peers:\n");
            for (size_t i = 0; i < peers_count; ++i) {
                Peer *p = (Peer *) (g_buf + offset);
                // peer_print(p); // FIXME actually validate
                offset += sizeof(Peer);
            }
        }
        fprintf(stderr, "\n");
    }
    
    return 0; // NOTE Success
}

int validate_received_data(const struct sockaddr_in *peer_address, const ssize_t recv_len, const Message *msg) {
    int ret = validate_received_length(recv_len, msg);
    validate_address(peer_address);
    if (msg->message == MSG_HELLO_REPLY) validate_peers(msg);
    return ret; // NOTE Potem, gdy nie będziemy rzucali syserr w przypadku recv_len < msg_size, będziemy mogli jakoś to lepiej obsłużyc
}

// TODO Usystematyzować wysyłanie

// TODO Możnaby to jakoś ujednolicić, żeby dołączający z _ar_provided też mógł użyć takiej funkcji
void establish_connection(const struct sockaddr_in *peer_address) {
    uint8_t ip[16];
    memset(ip, 0, sizeof(ip));
    memcpy(ip, &peer_address->sin_addr, IPV4_ADDR_LEN);

    Peer p;
    p.peer_address_length = IPV4_ADDR_LEN;
    memcpy(p.peer_address, ip, IPV4_ADDR_LEN);
    p.peer_port = peer_address->sin_port; // NOTE bez konwertowania

    peer_add(&p);
}

/** `msg_dest` should not be initialized. */
Message* msg_copy(const Message *msg_src) {
    // NOTE możemy opakować tego malloca
    Message *msg_cp = malloc(msg_size(msg_src));
    if (msg_cp == NULL) {
        syserr("malloc failed in msg_copy");
    }

    memcpy(msg_cp, msg_src, msg_size(msg_src));
    return msg_cp;
}

// NOTE za długa nazwa
// NOTE można by to uogólnić, jednak w sumie jakiekolwiek uogólnienie to po prostu memcpy :)
// peer_index to indeks typa, ktorego nie przesyłamy
void prepare_buffer_for_sending(const Message *msg, const ssize_t peer_index) {
    memcpy(g_buf, msg, msg_size(msg)); // Load message to buffer.
    
    if (msg->message == MSG_HELLO_REPLY) {
        size_t full_len = ntohs(((HelloReplyMessage *)msg)->count) * sizeof(Peer);
        void *src1  = g_peers;
        void *dest1 = g_buf + msg_size(msg);

        // Load peers to buffer
        if (peer_index == -1) {
            memcpy(dest1, src1, full_len);
        } else {
            // NOTE Czy sprawdzać, czy nie wychodzimy poza bufor?
            size_t len1 = peer_index * sizeof(Peer);
            size_t len2 = full_len - len1;
            void *src2  = src1 + len1 + sizeof(Peer);
            void *dest2 = dest1 + len1;

            memcpy(dest1, src1, len1);
            memcpy(dest2, src2, len2);
        }
            
        log_sending_peers(msg);
    }
}

/**
 * Jeśli nie bierzemy z g_buf: len=-1
 * Jeśli bierzemy z g_buf, to msg nie ma znaczenia
 */
ssize_t sendto_wrap(const struct sockaddr_in *peer_address, const Message *msg, ssize_t len) {
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    ssize_t send_len;

    if (len < 0) {
        send_len = sendto(g_socket_fd, msg, msg_size(msg), 0,
            (struct sockaddr *) peer_address, addr_len);
    } else {
        send_len = sendto(g_socket_fd, g_buf, len, 0,
            (struct sockaddr *) peer_address, addr_len);
    }

    if (send_len < 0) syserr("sendto fail"); // NOTE (chyba) Nie powinno się wywalać
    return send_len;
}

// TODO widać powtarzający się schemat, można to ujednolicić

/**
 * Jeśli nie bierzemy z g_buf: len=-1
 */
ssize_t send_message(const struct sockaddr_in *peer_address, const Message *msg, ssize_t len) {
    if (len < 0) {
        
    }

    ssize_t send_len = sendto_wrap(peer_address, msg, len);
    if (send_len > 0 ) log_sent_message(peer_address, msg, send_len);

    return send_len;
}

ssize_t send_hello(const struct sockaddr_in *peer_address) {
    HelloMessage msg = {
        .base.message = MSG_HELLO
    };

    return send_message(peer_address, (Message *)&msg, -1);
}

void send_hello_reply(const struct sockaddr_in *peer_address, SendInfo *sinfo) {
    Peer *p = peer_find(peer_address);
    sinfo->known = p != NULL;
    ssize_t pind = sinfo->known ? (uintptr_t) p - (uintptr_t) g_peers : -1;

    HelloReplyMessage msg = {
        .base.message = MSG_HELLO_REPLY,
        .count        = sinfo->known ? htons(g_count-1) : htons(g_count),
    };

    size_t full_len = msg_size((Message *)&msg) + ntohs(msg.count) * sizeof(Peer);
    prepare_buffer_for_sending((Message *)&msg, pind);
    sinfo->send_len = send_message(peer_address, (Message *)&msg, full_len);
}

ssize_t send_connect(struct sockaddr_in *peer_address) {
    ConnectMessage msg = {
        .base.message = MSG_CONNECT
    };

    return send_message(peer_address, (Message *)&msg, -1);
}

// TODO lepsza nazwa
void _connect(Peer *p) {
    if (p->peer_address_length != IPV4_ADDR_LEN) syserr("Wrong address");

    // TODO nie da sie sprytniej?
    char peer_ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, (struct in_addr *)p->peer_address, peer_ip_str, INET_ADDRSTRLEN) == NULL) {
        syserr("inet_ntop failed");
    }

    struct sockaddr_in peer_address = get_peer_address(peer_ip_str, ntohs(p->peer_port));
    send_connect(&peer_address);
}


ssize_t send_ack_connect(const struct sockaddr_in *peer_address) {
    AckConnectMessage msg = {
        .base.message = MSG_ACK_CONNECT
    };

    return send_message(peer_address, (Message *)&msg, -1);
}

ssize_t receive_message(struct sockaddr_in *peer_address) {
    socklen_t addr_len = (socklen_t) sizeof(*peer_address);
    ssize_t recv_len = recvfrom(g_socket_fd, g_buf, sizeof(g_buf), 0,
                                (struct sockaddr *) peer_address, &addr_len);
    int val = validate_received_data(peer_address, recv_len, (Message *)g_buf);
    (void)val; // NOTE nieużyta zmienna

    return recv_len;
}

// TODO ta funkcja jest aczytalna
uint8_t receive_and_handle_hello_reply(struct sockaddr_in *peer_address, Peer **peers) {
    HelloReplyMessage msg;

    ssize_t recv_len = receive_message(peer_address);

    // Deserialize Message structure.
    memcpy(&msg, g_buf, sizeof(HelloReplyMessage));
    log_received_message(peer_address, (Message *)&msg, recv_len);

    // Copy contents of peers
    uint16_t peers_count = ntohs(msg.count);
    if (peers_count > 0) {
        *peers = malloc(peers_count * sizeof(Peer));
        if (*peers == NULL) syserr("malloc failed");
        memcpy(*peers, g_buf + sizeof(msg), peers_count * sizeof(Peer));

        fprintf(stderr, "Peers from HELLO_REPLY:\n");
        for (size_t i = 0; i < peers_count; ++i) {
            // peer_convert_to_host(&(*peers)[i]);
            peer_print(&(*peers)[i]);
            // FIXME Validate!
        }
        fprintf(stderr, "\n");
    }

    // FIXME Jeśli jest niepoprawnie, to wynikiem powinno być 255 (czy to poprawne?)
    return peers_count;
}

// TODO czy mozna sensownie ujednolicic wysylanie, aby to tez mozna bylo dac do funkcji `msg_send`?
// TODO Posprzątać
void handle_hello(const struct sockaddr_in *peer_address) {
    SendInfo info;
    send_hello_reply(peer_address, &info);

    if (info.known) {
        establish_connection(peer_address);
    }
}

void handle_connect(const struct sockaddr_in *peer_address) {
    establish_connection(peer_address);
    send_ack_connect(peer_address);
}

void handle_ack_connect(const struct sockaddr_in *peer_address) {
    establish_connection(peer_address);
}

void handle_sync_start(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_delay_request(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_delay_response(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_leader(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

void handle_get_time(const Message *msg) {
    (void)msg;
    // TODO: Implement this function
}

void handle_time(const struct sockaddr_in *peer_address, const Message *msg) {
    (void)peer_address;
    (void)msg;
    // TODO: Implement this function
}

Message *msg_load() {
    Message *msg = malloc(sizeof(Message));
    if (msg == NULL) syserr("malloc msg_load");
    
    memcpy(msg, g_buf, sizeof(Message));
    size_t message_size = msg_size(msg);

    if (message_size > sizeof(Message)) {
        Message *tmp_msg = realloc(msg, message_size);
        if (tmp_msg == NULL) {
            free(msg);
            syserr("realloc msg_load");
        }

        msg = tmp_msg;
        memcpy((uint8_t *)msg + sizeof(Message), g_buf + sizeof(Message), message_size - sizeof(Message));
    }

    return msg;
}

void handle_message(const struct sockaddr_in *peer_address, const ssize_t recv_len) {
    Message *msg = msg_load(); // Interpret data as a Message structure.
    log_received_message(peer_address, msg, recv_len);
    
    if (!g_msg_info[msg->message].allow_unknown_sender &&
        peer_find(peer_address) == NULL) {
        syserr("Nie znom jo tego chłopa."); // NOTE nie powinno się wywalać, lecz chyba coś powinno wypisywać
    }

    // Można napisać coś o tym, czemu nie rozważamy MSG_HELLO_REPLY.
    // FIXME Jednak trzeba tu uwzględnić MSG_HELLO_REPLY, bo co jeśli węzeł ponownie dołącza do sieci i jakiś koleżka wyśle mu np SYNC_START?
    switch (msg->message) {
        case MSG_HELLO:
            handle_hello(peer_address);
            break;

        case MSG_CONNECT:
            handle_connect(peer_address);
            break;

        case MSG_ACK_CONNECT:
            handle_ack_connect(peer_address);
            break;

        case MSG_SYNC_START:
            handle_sync_start(peer_address, msg);
            break;

        case MSG_DELAY_REQUEST:
            handle_delay_request(peer_address, msg);
            break;

        case MSG_DELAY_RESPONSE:
            handle_delay_response(peer_address, msg);
            break;

        case MSG_LEADER:
            handle_leader(peer_address, msg);
            break;

        case MSG_GET_TIME:
            handle_get_time(msg);
            break;

        case MSG_TIME:
            handle_time(peer_address, msg);
            break;

        default:
            fprintf(stderr, "Unknown message type: %u\n", msg->message);
            break;
    }
}

void listen_for_messages() {
    struct sockaddr_in peer_address;

    // TODO czy nie powinniśmy poświęcać większej uwagi addr_len po recvfrom?
    while (true) {
        ssize_t recv_len = receive_message(&peer_address);
        handle_message(&peer_address, recv_len);
    }
}

void join_network(ProgramArgs args) {
    if (!args._ar_provided) return;

    struct sockaddr_in peer_address = get_peer_address(args.peer_address, args.peer_port);
    Peer *peers = NULL;

    Peer first;
    first.peer_address_length = IPV4_ADDR_LEN;
    if (inet_pton(AF_INET, args.peer_address, first.peer_address) != 1) {
        syserr("inet_pton failed");
    }
    first.peer_port = htons(args.peer_port);
    peer_add(&first);

    send_hello(&peer_address);
    uint16_t count = receive_and_handle_hello_reply(&peer_address, &peers);

    for (uint16_t i = 0; i < count; ++i) {
        _connect(&peers[i]);
    }
    free(peers);
}

int main(int argc, char* argv[]) {
    init_global();
    setup_signal_handler(); // Just for debugging I guess.
    init_msg_info();

    ProgramArgs program_args = args_default();
    args_parse(argc, argv, &program_args);
    args_validate(&program_args);

    struct sockaddr_in bind_address; // To avoid allocation on the stack.
    init_socket(&bind_address, program_args.bind_address, program_args.port);
    
    join_network(program_args);
    listen_for_messages();
    
    close(g_socket_fd);
    return 0;
}