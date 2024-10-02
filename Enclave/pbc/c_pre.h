// c_pre.h
#ifndef C_PRE_H 
#define C_PRE_H 
#include <stdio.h>
#include <string.h>
#include <pbc/pbc.h>


// extern pairing_t pairing;
// extern element_t g;
// extern int n;
// extern element_t Z;

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