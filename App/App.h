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


#ifndef _APP_H_
#define _APP_H_

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include "util.h"

#include "sgx_error.h"       /* sgx_status_t */
#include "sgx_eid.h"     /* sgx_enclave_id_t */

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

#define PRINT_DEBUG_INFO
#define TIME_COST

# define TOKEN_FILENAME   "enclave.token"
# define ENCLAVE_FILENAME "enclave.signed.so"

# define ERRORMSG_REQUEST_ERROR   "request error"
# define ERRORMSG_SGX_ERROR   "call sgx error"
# define ERRORMSG_FILE_IO_ERROR   "file io error"
# define ERRORMSG_MEMORY_ERROR   "memory allocate error"

extern sgx_enclave_id_t global_eid;    /* global enclave id */

#if defined(__cplusplus)
extern "C" {
#endif

int access_control(char *user_id, char *file_id);
int access_control_file(int fd, char *user_id, char *file_id);
int handleRequest(unsigned char *requestMsg, size_t requestMsgLen, int fd, 
        unsigned char *responseMsg, size_t * responseMsgLen);
int handleRequest0001(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseBody, size_t * responseBodyLength);
int handleRequest0002(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseBody, size_t * responseBodyLength);
int handleRequest0003(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseBody, size_t * responseBodyLength);
int handleRequest0004(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseBody, size_t * responseBodyLength);
int handleRequest0005(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseBody, size_t * responseBodyLength);
int handleRequest1001(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseBody, size_t * responseBodyLength);
int handleRequest1002(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength);
// the same as pre.h c_pre.h
#define ZR_ELEMENT_LENGTH_IN_BYTES 20
#define G1_ELEMENT_LENGTH_IN_BYTES 128
#define G2_ELEMENT_LENGTH_IN_BYTES 128
#define GT_ELEMENT_LENGTH_IN_BYTES 128
#define SHA256_DIGEST_LENGTH_32 32

typedef struct _pk_a_t{
    unsigned char Z_a1[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char g_a2[G1_ELEMENT_LENGTH_IN_BYTES];
} pk_a_t;

typedef struct _sk_a_t{
    unsigned char a1[ZR_ELEMENT_LENGTH_IN_BYTES];
    unsigned char a2[ZR_ELEMENT_LENGTH_IN_BYTES];
} sk_a_t;

typedef struct _key_pair_t{
    pk_a_t pk_a;
    sk_a_t sk_a; 
} key_pair_t;

/*
include c_a_1, c_a_2, c_a_r
*/
typedef struct _c_a_t{
    unsigned char Z_a1_k[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char Z_a2_k[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char m_Z_k[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char g_k[G1_ELEMENT_LENGTH_IN_BYTES];
    unsigned char m_Z_a1_k[GT_ELEMENT_LENGTH_IN_BYTES];
} c_a_t;

#if defined(__cplusplus)
}
#endif

#endif /* !_APP_H_ */
