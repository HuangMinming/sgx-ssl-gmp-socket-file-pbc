// c_pre.h
#ifndef __C_PRE__H
#define __C_PRE__H
#include <stdio.h>
#include <string.h>
#include <pbc.h>
#include "user_types.h" 


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
} KeyPairHex;

struct vk_A_t {
        unsigned char vk_A[BUF_SIZE];
        size_t vk_A_Length;
};

struct ShareFile_t {
    uint8_t owner_user_id[20 + 1];
    uint8_t shared_with_user_id[20 + 1];
    uint8_t share_id[50 + 1];
    uint8_t file_id[50 + 1];
    uint8_t file_name[256 + 1];
    uint8_t C_rk[568 + 1];
    uint8_t CDEK_rk_C1[256 + 1];
    uint8_t CDEK_rk_C2[256 + 1];
    uint8_t CDEK_rk_C3[512 + 1];
    uint8_t CDEK_rk_C4[256 + 1];
    uint8_t Cert_owner_info[600 + 1];
    uint8_t Cert_owner_info_sign_value[256 + 1];
    uint8_t owner_grant_info[2144 + 1];
    uint8_t owner_grant_info_sign_value[256 + 1];
    uint8_t C_DEK_C1[256 + 1];
    uint8_t C_DEK_C2[256 + 1];
    uint8_t C_DEK_C3[512 + 1];
    uint8_t C_DEK_C4[256 + 1];
};

#define UserRevocation_MAX_size 1024
#define user_id_MAX_size 21
struct UserRevocationList_t {
        size_t count = 0;
        unsigned char user_id[UserRevocation_MAX_size][user_id_MAX_size];  
};


// 函数声明


#endif