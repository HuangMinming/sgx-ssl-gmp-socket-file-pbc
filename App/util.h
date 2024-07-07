
#ifndef __UTIL_H_
#define __UTIL_H_

#include <stdint.h>

#define __is_print(ch) ((unsigned int)((ch) - ' ') < 127u - ' ')

void dump_hex(const uint8_t *buf, uint32_t size, uint32_t number);

#endif