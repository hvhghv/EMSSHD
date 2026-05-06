#ifndef EMSSH_TESTS_FUZZ_DECODE_COMMON_H
#define EMSSH_TESTS_FUZZ_DECODE_COMMON_H

#include <stddef.h>
#include <stdint.h>

void emssh_fuzz_exercise_decoders(const uint8_t *data, size_t data_len);
void emssh_fuzz_mutate_seed(const uint8_t *seed, size_t seed_len);

#endif
