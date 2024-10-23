// c_pre.h
#ifndef __C_PRE__H
#define __C_PRE__H
#include <stdio.h>
#include <string.h>
#include <pbc.h>

#define PRINT_DEBUG_INFO

#define SHA256_DIGEST_LENGTH_32 32
#define ZR_ELEMENT_LENGTH_IN_BYTES 20
#define G1_ELEMENT_LENGTH_IN_BYTES 128
#define G2_ELEMENT_LENGTH_IN_BYTES 128
#define GT_ELEMENT_LENGTH_IN_BYTES 128

// 结构体定义
typedef struct {
    element_t pk;   // 公钥 G1
    element_t sk;   // 私钥 Zr
} KeyPair;

typedef struct {
    element_t rk1;  // 重加密密钥 rk1  G1
    element_t rk2;  // 重加密密钥 rk2  G1
} ReKeyPair;

typedef struct {
    element_t c1;   // 密文的第一部分 G1
    element_t c2;   // 密文的第二部分 GT
    uint8_t *c3;       // 密文的第三部分（比特串）
    element_t c4;   // 密文的第四部分  G1
} CipherText;

typedef struct {
    uint8_t pk_Hex[G1_ELEMENT_LENGTH_IN_BYTES * 2];   // 公钥 G1
    uint8_t sk_Hex[ZR_ELEMENT_LENGTH_IN_BYTES * 2];   // 私钥 Zr
} KeyPair_Hex;


// 函数声明


#endif