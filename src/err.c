#include <stdio.h>
#include <stdlib.h>

#include "../include/err.h"

// TODO: Skopiować mimową bibliotekę errorową.
void syserr(const char *msg) {
    fprintf(stderr, "%s, exiting...\n", msg);
    exit(1);
}
