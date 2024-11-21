// c_pre.h
#ifndef __SSL__H
#define __SSL__H
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
const int IV_LEN = 12;
const int TAG_SIZE = 16;
const int KEY_SIZE = 32;
// 函数声明
void exit(int status);
void handleErrors(char *x);
int ecdsa_verify(char * public_key, size_t public_key_len, 
    char *msg, size_t msg_len, 
    u_char *sigHex, size_t sigHex_len);
int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag);
int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag, unsigned char *key, unsigned char *iv,
                int iv_len, unsigned char *plaintext);
#endif