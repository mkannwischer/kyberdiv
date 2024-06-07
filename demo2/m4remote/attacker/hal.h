#ifndef HAL_H
#define HAL_H

#include <stdint.h>
#include <stdlib.h>

enum clock_mode {
    CLOCK_FAST,
    CLOCK_BENCHMARK
};

void hal_setup(const enum clock_mode clock);
void hal_send_str_host(const char* in);
void hal_send_str_victim(const char* in);
void hal_send_char_victim(char in);
void hal_send_bytes_victim(const unsigned char *in, unsigned int n);

void hal_recv_bytes_host(unsigned char *out, unsigned int n);
void hal_recv_str_victim(char *out, unsigned int n);
uint64_t hal_get_time(void);
size_t hal_get_stack_size(void);

#endif
