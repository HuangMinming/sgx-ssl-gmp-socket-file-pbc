#include "util.h"
#include <stdio.h>

/**
 * dump_hex
 * 
 * @brief dump data in hex format
 * 
 * @param buf: User buffer
 * @param size: Dump data size
 * @param number: The number of outputs per line
 * 
 * @return void
*/
void dump_hex(const uint8_t *buf, uint32_t size, uint32_t number)
{
    int i, j;

    for (i = 0; i < size; i += number)
    {
        printf("%08X: ", i);

        for (j = 0; j < number; j++)
        {
            if (j % 8 == 0)
            {
                printf(" ");
            }
            if (i + j < size)
                printf("%02X ", buf[i + j]);
            else
                printf("   ");
        }
        printf(" ");

        for (j = 0; j < number; j++)
        {
            if (i + j < size)
            {
                printf("%c", __is_print(buf[i + j]) ? buf[i + j] : '.');
            }
        }
        printf("\n");
    }
}