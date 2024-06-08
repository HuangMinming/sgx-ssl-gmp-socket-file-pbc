/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <sgx_trts.h>
#include "tSgxSSL_api.h"
#include "pbc.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define ADD_ENTROPY_SIZE 32

/*
 * printf:
 *   Invokes OCALL to display the enclave buffer to the terminal.
 */
int sgx_printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

int vprintf_cb(Stream_t stream, const char *fmt, va_list arg)
{
    char buf[BUFSIZ] = {'\0'};

    int res = vsnprintf(buf, BUFSIZ, fmt, arg);
    if (res >= 0)
    {
        sgx_status_t sgx_ret = ocall_print_string((const char *)buf);
        TEST_CHECK((int)sgx_ret);
    }
    return res;
}

/* t_ecall_data_in_out:
 *   data[] will be allocated inside the enclave, content of data[] will be copied either.
 *   After ECALL returns, the results will be copied to the outside.
 */
size_t t_ecall_data_in_out(char data[BUF_SIZE])
{

    for (int i = 0; i < BUF_SIZE; i++)
    {
        // sgx_printf("%c", data[i]);
        data[i] = 'a' + (i % 26);
    }
    return BUF_SIZE;
}

/* t_ecall_data_deal:
 *   data_in[] is copied to trusted domain, but modified
 *   results will not be reflected to the untrusted side.
 *   data_out[] is allocated inside the enclave, and it will be copied
 *   to the untrusted side
 */
size_t t_ecall_data_deal(char data_in[BUF_SIZE], char data_out[BUF_SIZE_SMALL])
{
    for (int i = 0; i < BUF_SIZE_SMALL; i++)
    {
        // sgx_printf("%c", data_in[i]);
        data_out[i] = 'a' + (i % 26);
        // data_out[i] = data_in[i];
    }
    return BUF_SIZE_SMALL;
}

void ecall_pointer_size(void* ptr, size_t len)
{
    strncpy((char*)ptr, "0987654321", strlen("0987654321"));
}

pairing_t pairing;
void t_sgxpbc_call_apis(unsigned char *ptr1, size_t len1, unsigned char *ptr2, size_t len2)
{
    sgx_printf("ok1\n");
    element_t sk, pk, signature, h, g;
    char message[] = "Hello, world!";

    // Initialize pairing
    char param_str[] = "type a\n"
                       "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
                       "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
                       "r 730750818665451621361119245571504901405976559617\n"
                       "exp2 159\n"
                       "exp1 107\n"
                       "sign1 1\n"
                       "sign0 1";
    pbc_param_t par;
    pbc_param_init_set_str(par, param_str);
    pairing_init_pbc_param(pairing, par);

    // Initialize elements
    element_init_Zr(sk, pairing);
    element_init_G1(signature, pairing);
    element_init_G1(h, pairing);
    element_init_G1(g, pairing);
    element_init_G1(pk, pairing);

    // Generate data
    element_random(sk); // x
    element_random(g);

    // Generate signature
    element_from_hash(h, message, strlen(message));
    element_pow_zn(signature, h, sk); // h^x
    element_pow_zn(pk, g, sk); // g^x

    // Verify signature
    element_t e1, e2;
    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);

    pairing_apply(e1, signature, g, pairing); // e(signature,g)
    pairing_apply(e2, h, pk, pairing);       // e(h,g^x)


    if (element_cmp(e1, e2) == 0) {
        sgx_printf("Signature verified successfully.\n");
    } else {
        sgx_printf("Failed to verify signature.\n");
    }

    size_t n1 = element_length_in_bytes(e1);
    unsigned char *data1 = (unsigned char *)malloc(n1);
    sgx_printf("n1 = %d.\n data1 = ", n1);
    element_to_bytes(data1, e1);
    for(int i=0;i<n1;i++) {
        sgx_printf("%02x ", data1[i]);
    }
    sgx_printf("\n");
    // for(int i=0;i<n1;i++) {
    //     ptr1[i] = data1[i];
    // }
    memcpy(ptr1, data1, n1);

    size_t n2 = element_length_in_bytes(e2);
    unsigned char *data2 = (unsigned char *)malloc(n2);
    sgx_printf("n2 = %d.\n data2 = ", n2);
    element_to_bytes(data2, e2);
    for(int i=0;i<n2;i++) {
        sgx_printf("%02x ", data2[i]);
    }
    sgx_printf("\n");
    // for(int i=0;i<n2;i++) {
    //     ptr2[i] = data2[i];
    // }
    memcpy(ptr2, data2, n2);

    // element_t e3, e4;
    // element_init_GT(e3, pairing);
    // element_init_GT(e4, pairing);
    // element_from_bytes(e3, data1);
    // element_from_bytes(e4, data2);
    // if (element_cmp(e3, e4) == 0) {
    //     sgx_printf("e3 == e4.\n");
    // } else {
    //     sgx_printf("e3 != e4.\n");
    // }   
        

    // Clear elements
    // free(data1);
    // free(data2);
    // element_clear(e3);
    // element_clear(e4);
    element_clear(e1);
    element_clear(e2);
    element_clear(sk);
    element_clear(pk);
    element_clear(signature);
    element_clear(h);
    element_clear(g);
    // pairing_clear(pairing);
}

void t_sgxpbc_call_free_pairing() {
    pairing_clear(pairing);
}

void t_sgxpbc_call_test(unsigned char *ptr1, size_t len1, unsigned char *ptr2, size_t len2)
{
    
    element_t e3, e4;
    element_init_GT(e3, pairing);
    element_init_GT(e4, pairing);
    element_from_bytes(e3, ptr1);
    element_from_bytes(e4, ptr2);
    if (element_cmp(e3, e4) == 0) {
        sgx_printf("e3 == e4.\n");
    } else {
        sgx_printf("e3 != e4.\n");
    }   
        

    // Clear elements
    // free(data1);
    // free(data2);
    element_clear(e3);
    element_clear(e4);
}

void t_sgxpbc_call_apis3()
{
    pairing_t pairing;
    element_t sk, pk, signature, h, g;
    char message[] = "Hello, world!";

    // Initialize pairing
    char param_str[] = "type a\n"
                       "q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n"
                       "h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n"
                       "r 730750818665451621361119245571504901405976559617\n"
                       "exp2 159\n"
                       "exp1 107\n"
                       "sign1 1\n"
                       "sign0 1";
    pbc_param_t par;
    pbc_param_init_set_str(par, param_str);
    pairing_init_pbc_param(pairing, par);

    // Initialize elements
    element_init_Zr(sk, pairing);
    element_init_G1(signature, pairing);
    element_init_G1(h, pairing);
    element_init_G1(g, pairing);
    element_init_G1(pk, pairing);

    // Generate data
    element_random(sk); // x
    element_random(g);

    // Generate signature
    element_from_hash(h, message, strlen(message));
    element_pow_zn(signature, h, sk); // h^x
    element_pow_zn(pk, g, sk); // g^x

    // Verify signature
    element_t e1, e2;
    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);

    pairing_apply(e1, signature, g, pairing); // e(signature,g)
    pairing_apply(e2, h, pk, pairing);       // e(h,g^x)


    if (element_cmp(e1, e2) == 0) {
        sgx_printf("Signature verified successfully.\n");
    } else {
        sgx_printf("Failed to verify signature.\n");
    }

    size_t n1 = element_length_in_bytes(e1);
    unsigned char *data1 = (unsigned char *)malloc(n1);
    sgx_printf("n1 = %d.\n data1 = ", n1);
    element_to_bytes(data1, e1);
    for(int i=0;i<n1;i++) {
        sgx_printf("%02x ", data1[i]);
    }
    sgx_printf("\n");

    size_t n2 = element_length_in_bytes(e2);
    unsigned char *data2 = (unsigned char *)malloc(n2);
    sgx_printf("n2 = %d.\n data2 = ", n2);
    element_to_bytes(data2, e2);
    for(int i=0;i<n2;i++) {
        sgx_printf("%02x ", data2[i]);
    }
    sgx_printf("\n");

    element_t e3, e4;
    element_init_GT(e3, pairing);
    element_init_GT(e4, pairing);
    sgx_printf("ok1.\n");
    element_from_bytes(e3, data1);
    sgx_printf("ok2.\n");
    element_from_bytes(e4, data2);
    sgx_printf("ok3.\n");
    if (element_cmp(e3, e4) == 0) {
        sgx_printf("e3 == e4.\n");
    } else {
        sgx_printf("e3 != e4.\n");
    }   
        

    // Clear elements
    free(data1);
    free(data2);
    element_clear(e3);
    element_clear(e4);
    element_clear(e1);
    element_clear(e2);
    element_clear(sk);
    element_clear(pk);
    element_clear(signature);
    element_clear(h);
    element_clear(g);
    pairing_clear(pairing);
}

void t_sgxpbc_call_apis2()
{
    pairing_t pairing;
    element_t g, h;
    element_t public_key, sig;
    element_t secret_key;
    element_t temp1, temp2;

    //   pbc_demo_pairing_init(pairing, argc, argv);
    char *s = "type a\n\
q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n\
h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n\
r 730750818665451621361119245571504901405976559617\n\
exp2 159\n\
exp1 107\n\
sign1 1\n\
sign0 1";
    pairing_init_set_str(pairing, s); // Where s is a char *.

    element_init_G2(g, pairing);
    element_init_G2(public_key, pairing);
    element_init_G1(h, pairing);
    element_init_G1(sig, pairing);
    element_init_GT(temp1, pairing);
    element_init_GT(temp2, pairing);
    element_init_Zr(secret_key, pairing);

    sgx_printf("Short signature test\n");

    // generate system parameters
    element_random(g);
    // element_printf("system parameter g = %B\n", g);

    // generate private key
    element_random(secret_key);
    // element_printf("private key = %B\n", secret_key);

    // compute corresponding public key
    element_pow_zn(public_key, g, secret_key);
    // element_printf("public key = %B\n", public_key);

    // generate element from a hash
    // for toy pairings, should check that pairing(g, h) != 1
    element_from_hash(h, (void *)"hashofmessage", 13);
    // element_printf("message hash = %B\n", h);

    // h^secret_key is the signature
    // in real life: only output the first coordinate
    element_pow_zn(sig, h, secret_key);
    // element_printf("signature = %B\n", sig);

    {
        int n = pairing_length_in_bytes_compressed_G1(pairing);
        // int n = element_length_in_bytes_compressed(sig);
        int i;
        unsigned char *data = (unsigned char *)pbc_malloc(n);

        element_to_bytes_compressed(data, sig);
        sgx_printf("compressed = ");
        for (i = 0; i < n; i++)
        {
            sgx_printf("%02X", data[i]);
        }
        sgx_printf("\n");

        element_from_bytes_compressed(sig, data);
        // element_printf("decompressed = %B\n", sig);

        pbc_free(data);
    }

    // verification part 1
    element_pairing(temp1, sig, g);
    // element_printf("f(sig, g) = %B\n", temp1);

    // verification part 2
    // should match above
    element_pairing(temp2, h, public_key);
    // element_printf("f(message hash, public_key) = %B\n", temp2);

    if (!element_cmp(temp1, temp2))
    {
        sgx_printf("signature verifies\n");
    }
    else
    {
        sgx_printf("*BUG* signature does not verify *BUG*\n");
    }

    {
        int n = pairing_length_in_bytes_x_only_G1(pairing);
        // int n = element_length_in_bytes_x_only(sig);
        int i;
        unsigned char *data = (unsigned char *)pbc_malloc(n);

        element_to_bytes_x_only(data, sig);
        sgx_printf("x-coord = ");
        for (i = 0; i < n; i++)
        {
            sgx_printf("%02X", data[i]);
        }
        sgx_printf("\n");

        element_from_bytes_x_only(sig, data);
        // element_printf("de-x-ed = %B\n", sig);

        element_pairing(temp1, sig, g);
        if (!element_cmp(temp1, temp2))
        {
            sgx_printf("signature verifies on first guess\n");
        }
        else
        {
            element_invert(temp1, temp1);
            if (!element_cmp(temp1, temp2))
            {
                sgx_printf("signature verifies on second guess\n");
            }
            else
            {
                sgx_printf("*BUG* signature does not verify *BUG*\n");
            }
        }

        pbc_free(data);
    }

    // a random signature shouldn't verify
    element_random(sig);
    element_pairing(temp1, sig, g);
    if (element_cmp(temp1, temp2))
    {
        sgx_printf("random signature doesn't verify\n");
    }
    else
    {
        sgx_printf("*BUG* random signature verifies *BUG*\n");
    }

    element_clear(sig);
    element_clear(public_key);
    element_clear(secret_key);
    element_clear(g);
    element_clear(h);
    element_clear(temp1);
    element_clear(temp2);
    pairing_clear(pairing);
}
