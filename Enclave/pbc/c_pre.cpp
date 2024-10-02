#include <stdio.h>
#include <pbc.h>
#include <string.h>
#include "../Enclave.h"
#include "../Enclave_t.h" /* print_string */
#include "../sha256.h"

#include "c_pre.h"


#define g_str "31415926"

void Setup(pairing_t pairing, element_t g, element_t Z, int *p_n)
{
    char *param="type a\n\
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n\
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\
r 730750818665451621361119245571504901405976559617\n\
exp2 159\n\
exp1 107\n\
sign1 1\n\
sign0 1";
    // size_t count = fread(param, 1, 1024, stdin);
    // if (!count)
    //     pbc_die("input error");
    size_t count = strlen(param);
    sgx_printf("count=%d\n", count);
    pairing_init_set_buf(pairing, param, count);
    element_init_G1(g, pairing);
    // element_random(g);
    element_from_hash(g, (void*)g_str, strlen(g_str));
    element_init_GT(Z, pairing);
    pairing_apply(Z, g, g, pairing);
    (*p_n) = 50;
    unsigned char g_data[1024];
    size_t g_len = element_length_in_bytes(g);
    element_to_bytes(g_data, g);
    sgx_printf("g_len = %d, g=\n", g_len);
    for(int i=0;i<g_len;i++){
        sgx_printf("%02x ", g_data[i]);
    }
    sgx_printf("\n");
    unsigned char Z_data[1024];
    size_t Z_len = element_length_in_bytes(Z);
    element_to_bytes(Z_data, Z);
    sgx_printf("Z_len = %d, Z=\n", Z_len);
    for(int i=0;i<Z_len;i++){
        sgx_printf("%02x ", Z_data[i]);
    }
    sgx_printf("\n");   
}

int KeyGen(unsigned char *pk, int *p_pk_len, unsigned char *sk, int *p_sk_len)
{
    pairing_t pairing;
    element_t g;
    element_t Z;
    int n;
    KeyPair keypair;
    Setup(pairing, g, Z, &n);

    unsigned char g_data[1024];
    size_t g_len = element_length_in_bytes(g);
    element_to_bytes(g_data, g);
    sgx_printf("g_len = %d, g=\n", g_len);
    for(int i=0;i<g_len;i++){
        sgx_printf("%02x ", g_data[i]);
    }
    sgx_printf("\n");

    sgx_printf("n=%d\n", n);

    element_init_G1(keypair.pk, pairing);
    element_init_Zr(keypair.sk, pairing);
    element_random(keypair.sk);
    element_pow_zn(keypair.pk, g, keypair.sk);

    size_t pk_len = element_length_in_bytes(keypair.pk);
    size_t sk_len = element_length_in_bytes(keypair.sk);
    
    unsigned char pk_data[1024];
    unsigned char sk_data[1024];

    (*p_pk_len) = element_to_bytes(pk_data, keypair.pk);
    (*p_sk_len) = element_to_bytes(sk_data, keypair.sk);

    memcpy(pk, pk_data, (*p_pk_len));
    memcpy(sk, sk_data, (*p_sk_len));

    sgx_printf("(*p_pk_len) = %d, pk_data=\n", g_len);
    for(int i=0;i<(*p_pk_len);i++){
        sgx_printf("%02x ", pk_data[i]);
    }
    sgx_printf("\n");

    return 0;
}


int c_pre_main_test() {

    unsigned char pk[1024];
    unsigned char sk[1024];
    int pk_len;
    int sk_len;
    KeyGen(pk, &pk_len, sk, &sk_len);

    sgx_printf("pk_len = %d, pk=\n", pk_len);
    for(int i=0;i<pk_len;i++) {
        sgx_printf("%02x ", pk[i]);
    }
    sgx_printf("\n");
    sgx_printf("sk_len = %d, sk=\n", sk_len);
    for(int i=0;i<sk_len;i++) {
        sgx_printf("%02x ", sk[i]);
    }
    sgx_printf("\n");


    return 0;
}