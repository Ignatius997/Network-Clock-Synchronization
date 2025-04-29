#include <stdbool.h>
#include <stdio.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../include/args.h"
#include "../include/common.h"
#include "../include/err.h"

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
    fprintf(stderr, "\n");
}