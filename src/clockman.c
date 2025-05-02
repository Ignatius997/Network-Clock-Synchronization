#include <time.h>
#include <inttypes.h>
#include <stdio.h>

#include "../include/clockman.h"

static uint64_t natural_clock = 0;
static struct timespec program_start_time; // Czas startu programu

void clk_init(void) {
    clock_gettime(CLOCK_MONOTONIC, &program_start_time);
}

void clk_update(void) {
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);

    uint64_t elapsed_sec = current_time.tv_sec - program_start_time.tv_sec;
    uint64_t elapsed_nsec = current_time.tv_nsec - program_start_time.tv_nsec;

    natural_clock = elapsed_sec * 1000 + elapsed_nsec / 1000000; // Konwersja na ms
}

void clk_print(void) {
    fprintf(stderr, "natural clock: %" PRIu64 "\n", natural_clock);
}
