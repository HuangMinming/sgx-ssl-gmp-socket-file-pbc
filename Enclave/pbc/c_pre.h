// c_pre.h
#ifndef __C_PRE__H
#define __C_PRE__H
#include <stdio.h>
#include <string.h>
#include <pbc.h>

#define SHA256_DIGEST_LENGTH_32 32

// 结构体定义
typedef struct {
    element_t pk;   // 公钥
    element_t sk;   // 私钥
} KeyPair;

typedef struct {
    element_t rk1;  // 重加密密钥 rk1
    element_t rk2;  // 重加密密钥 rk2
} ReKeyPair;

typedef struct {
    element_t c1;   // 密文的第一部分
    element_t c2;   // 密文的第二部分
    char *c3;       // 密文的第三部分（比特串）
    element_t c4;   // 密文的第四部分
} CipherText;


// 函数声明
void Setup(pairing_t pairing, element_t g, element_t Z, int *p_n);

#endif