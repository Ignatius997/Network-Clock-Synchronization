#ifndef CLOCKMAN_H
#define CLOCKMAN_H

void clk_init(void);
void clk_start_tmp(void);

void clk_update_nat(void);
void clk_update_tmp(void);

void clk_print_nat(void);
void clk_print_tmp(void);

uint64_t clk_get_nat(void);
uint64_t clk_get_tmp(void);

#endif // CLOCKMAN_H