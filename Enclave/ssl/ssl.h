// c_pre.h
#ifndef __SSL__H
#define __SSL__H
#include <stdio.h>
#include <string.h>


// 函数声明
int ecdsa_verify(char * public_key, size_t public_key_len, 
    char *msg, size_t msg_len, 
    u_char *sigHex, size_t sigHex_len);

#endif