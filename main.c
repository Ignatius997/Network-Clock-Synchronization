#include <stdint.h>
#include <arpa/inet.h> // TODO: sugerowane niby netinet/in, ale na labach jest arpa.
#include <stdbool.h>
#include <regex.h>
#include <stdio.h>
#include <errno.h>

#define DEFAULT_PORT 0
#define ARGOPT_BIND_ADDRESS 'b'
#define ARGOPT_PORT         'p'
#define ARGOPT_PEER_ADDRESS 'a'
#define ARGOPT_PEER_PORT    'r'

typedef struct ProgramArgs {
    char *bind_address;
    uint16_t port;
    char *peer_address;
    uint16_t peer_port;
} ProgramArgs;

ProgramArgs default_program_args() {
    return (ProgramArgs) {
        .bind_address = NULL,
        .port = DEFAULT_PORT,
        .peer_address = NULL,
        .peer_port = DEFAULT_PORT,
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

// TODO Komentarz.
void load_arg_value(char const *arg, const char opt, ProgramArgs *program_args) {
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
void parse_args(int argc, char* argv[], ProgramArgs *program_args) {
    regex_t argopt_regex = argument_option_regex();

    // FIXME: Ewentualnie można zamienić na sprawdzanie parzystości i.
    bool option = true; // Tells, whether a flag an option, i.e. "-b" is required.
    char opt;

    for (int i = 1; i < argc; ++i) {
        if (option) {
            if (regexec(&argopt_regex, argv[i], 0, NULL, 0) != 0) {
                syserr("Wrong parameters!");
            } else {
                opt = argv[i][1];
            }
        } else {
            load_arg_value(argv[i], opt, program_args);
        }

        option = !option;
    }

    regfree(&argopt_regex);
}

int main(int argc, char* argv[]) {
    ProgramArgs program_args = default_program_args();
    parse_args(argc, argc, &program_args);

    return 0;
}