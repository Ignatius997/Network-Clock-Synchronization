#include <time.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>

#include "../include/clockman.h"

static bool initialized = false;

static uint64_t natural_clock = 0;
static uint64_t temporary_clock = 0;

static struct timespec program_start_time; // Czas startu programu
static struct timespec temporary_start_time; // Tymczasowy czas odniesienia

void clk_init(void) {
    if (!initialized) {
        clock_gettime(CLOCK_MONOTONIC, &program_start_time);
        temporary_start_time = program_start_time;
        initialized = true;
    }
}

void _update(uint64_t *clock, const struct timespec *start_time) {
    struct timespec current_time;
    clock_gettime(CLOCK_MONOTONIC, &current_time);

    uint64_t elapsed_sec = current_time.tv_sec - start_time->tv_sec;
    uint64_t elapsed_nsec = current_time.tv_nsec - start_time->tv_nsec;

    *clock = elapsed_sec * 1000 + elapsed_nsec / 1000000; // Convertion to ms.
}

void clk_start_tmp(void) {
    clock_gettime(CLOCK_MONOTONIC, &temporary_start_time); // Set new reference point.
}

void clk_update_nat(void) {
    _update(&natural_clock, &program_start_time);
}

void clk_update_tmp(void) {
    _update(&temporary_clock, &temporary_start_time);
}

void clk_print_nat(void) {
    fprintf(stderr, "natural clock: %" PRIu64 "\n", natural_clock);
}

void clk_print_tmp(void) {
    fprintf(stderr, "temporary clock: %" PRIu64 " ms\n", temporary_clock);
}
