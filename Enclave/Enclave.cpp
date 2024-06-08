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