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
#include <ctype.h>


#include <sgx_trts.h>
#include <mbusafecrt.h>
#include "sgx_tseal.h"
#include "tSgxSSL_api.h"
#include "pbc.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define ADD_ENTROPY_SIZE 32



#define bList_U_MAX_size 1024
#define user_id_MAX_size 21
struct bList_U_t {
        size_t user_count = 0;
        unsigned char user_id[bList_U_MAX_size][user_id_MAX_size];  
};

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

void ecall_pointer_size(void *ptr, size_t len)
{
    strncpy((char *)ptr, "0987654321", strlen("0987654321"));
}

char encrypt_data[BUFSIZ] = "Data to encrypt";
char aad_mac_text[BUFSIZ] = "aad mac text";

bList_U_t g_bList_U;
char aad_bList_U_mac_text[BUFSIZ] = "bList_U";


uint32_t get_sealed_data_size()
{
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));
}

sgx_status_t seal_data(uint8_t *sealed_blob, uint32_t data_size)
{
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_mac_text), (uint32_t)strlen(encrypt_data));
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t err = sgx_seal_data((uint32_t)strlen(aad_mac_text), (const uint8_t *)aad_mac_text, (uint32_t)strlen(encrypt_data), (uint8_t *)encrypt_data, sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}

sgx_status_t unseal_data(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text = (uint8_t *)malloc(mac_text_len);
    if (de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if (decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, &mac_text_len, decrypt_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    if (memcmp(de_mac_text, aad_mac_text, strlen(aad_mac_text)) || memcmp(decrypt_data, encrypt_data, strlen(encrypt_data)))
    {
        ret = SGX_ERROR_UNEXPECTED;
    }

    free(de_mac_text);
    free(decrypt_data);
    return ret;
}


sgx_status_t t_user_leave(const unsigned char *ptr_userId, size_t userIdLength)
{
    if(g_bList_U.user_count >= bList_U_MAX_size) 
    {
        sgx_printf("g_bList_U out of memory, user_count is : %d\n", g_bList_U.user_count);
        return SGX_ERROR_UNEXPECTED;
    }
    if(userIdLength >= user_id_MAX_size) 
    {
        sgx_printf("user_id too long, userIdLength is : %d\n", userIdLength);
        return SGX_ERROR_UNEXPECTED;
    }
    memset(g_bList_U.user_id[g_bList_U.user_count], 0x00, 
        sizeof(g_bList_U.user_id[g_bList_U.user_count]));
    memcpy(g_bList_U.user_id[g_bList_U.user_count], ptr_userId, userIdLength);
    g_bList_U.user_count ++;
    return SGX_SUCCESS;

}

uint32_t get_sealed_bList_U_data_size()
{
    return sgx_calc_sealed_data_size((uint32_t)strlen(aad_bList_U_mac_text), 
        (uint32_t)(sizeof(g_bList_U.user_id[0]) * g_bList_U.user_count));
}

sgx_status_t seal_bList_U_data(uint8_t *sealed_blob, uint32_t data_size)
{ 
    size_t len = sizeof(g_bList_U.user_id[0]) * g_bList_U.user_count;
    uint32_t sealed_data_size = sgx_calc_sealed_data_size((uint32_t)strlen(aad_bList_U_mac_text), 
        (uint32_t)len);
    if (sealed_data_size == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (sealed_data_size > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    unsigned char *data_buf = (unsigned char *)malloc(len);
    if (data_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    char user_countStr[5];
    memset(data_buf, 0x00, sizeof(data_buf));
    memset(user_countStr, 0x00, sizeof(user_countStr));
    sprintf_s(user_countStr, 5, "%04d", g_bList_U.user_count);

    memcpy(data_buf, user_countStr, 4);
    memcpy(data_buf + 4, g_bList_U.user_id, len);
    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    sgx_status_t err = sgx_seal_data((uint32_t)strlen(aad_bList_U_mac_text), 
        (const uint8_t *)aad_bList_U_mac_text, (uint32_t)len, (uint8_t *)data_buf, 
        sealed_data_size, (sgx_sealed_data_t *)temp_sealed_buf);
    if (err == SGX_SUCCESS)
    {
        // Copy the sealed data to outside buffer
        memcpy(sealed_blob, temp_sealed_buf, sealed_data_size);
    }

    free(temp_sealed_buf);
    return err;
}


sgx_status_t unseal_bList_U_data(const uint8_t *sealed_blob, size_t data_size)
{
    uint32_t mac_text_len = sgx_get_add_mac_txt_len((const sgx_sealed_data_t *)sealed_blob);
    uint32_t decrypt_data_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t *)sealed_blob);
    if (mac_text_len == UINT32_MAX || decrypt_data_len == UINT32_MAX)
        return SGX_ERROR_UNEXPECTED;
    if (mac_text_len > data_size || decrypt_data_len > data_size)
        return SGX_ERROR_INVALID_PARAMETER;

    uint8_t *de_mac_text = (uint8_t *)malloc(mac_text_len);
    if (de_mac_text == NULL)
        return SGX_ERROR_OUT_OF_MEMORY;
    uint8_t *decrypt_data = (uint8_t *)malloc(decrypt_data_len);
    if (decrypt_data == NULL)
    {
        free(de_mac_text);
        return SGX_ERROR_OUT_OF_MEMORY;
    }

    sgx_status_t ret = sgx_unseal_data((const sgx_sealed_data_t *)sealed_blob, de_mac_text, 
        &mac_text_len, decrypt_data, &decrypt_data_len);
    if (ret != SGX_SUCCESS)
    {
        free(de_mac_text);
        free(decrypt_data);
        return ret;
    }

    if (memcmp(de_mac_text, aad_bList_U_mac_text, strlen(aad_bList_U_mac_text)))
    {
        ret = SGX_ERROR_UNEXPECTED;
    }
    
    if(decrypt_data_len <  4)
    {
        return SGX_ERROR_UNEXPECTED;
    }

    char user_countStr[5];
    memset(user_countStr, 0x00, sizeof(user_countStr));

    memcpy(user_countStr, decrypt_data, 4);
    g_bList_U.user_count = atoi(user_countStr);

    size_t len = sizeof(g_bList_U.user_id[0]) * g_bList_U.user_count;

    memcpy(g_bList_U.user_id, decrypt_data + 4, len);

    sgx_printf("g_bList_U.user_count: %d\n", g_bList_U.user_count);
    for(int i=0;i<g_bList_U.user_count;i++) {
        sgx_printf("%s\n", g_bList_U.user_id[i]);
    }
    sgx_printf("\n");
    sgx_printf("unseal bList_U ok\n");

    free(de_mac_text);
    free(decrypt_data);
    return ret;
}


/*
 “233A464C52” ==>[0x23, 0x3A, 0x46, 0x4C, 0x52]
*/
uint32_t HexStrToByteStr(const uint8_t * src_buf, int src_len, uint8_t * dest_buf)
{
    uint8_t highByte, lowByte;
    if(NULL == src_buf)
		return 1;
	const uint8_t * index = src_buf, * end = src_buf + src_len;
    uint8_t * ridx = dest_buf;
    
    while (index < end)
    {
        highByte = tolower(* (index ++));
        lowByte  = tolower(* (index ++));

        if (highByte > 0x39)
            highByte -= 0x57;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x57;
        else
            lowByte -= 0x30;

        *ridx ++ = (highByte << 4) | lowByte;
    }
    return 0;
}

/*
 “233A464C52” ==>[0x23, 0x3A, 0x46, 0x4C, 0x52]
const uint8_t * src_buf: input, point to the source
int src_len: input, indicate the source length, should greater than 0, should be devided by 2
uint8_t * dest_buf: output, point to the destination
int dest_len: input, indicate the destination length, 
        should be greater or equal than src_len / 2
*/
int HexStrToByteStr2(const uint8_t * src_buf, int src_len, 
    uint8_t * dest_buf, int dest_len)
{
    if(NULL == src_buf || NULL == dest_buf ||
         src_len <= 0 || 
         (src_len % 2 != 0) ||
         (dest_len < src_len / 2)
         )
	{
        printf("HexStrToByteStr input error\n");
        return -1;
    }	
    uint8_t highByte, lowByte;
	const uint8_t * index = src_buf, * end = src_buf + src_len;
    uint8_t * ridx = dest_buf;
    
    while (index < end)
    {
        highByte = tolower(* (index ++));
        lowByte  = tolower(* (index ++));

        if (highByte > 0x39)
            highByte -= 0x57;
        else
            highByte -= 0x30;

        if (lowByte > 0x39)
            lowByte -= 0x57;
        else
            lowByte -= 0x30;

        *ridx ++ = (highByte << 4) | lowByte;
    }
    return 0;
}

/*
[0x23, 0x3A, 0x46, 0x4C, 0x52] ==> “233A464C52”
const uint8_t * src_buf: input, point to the source
int src_len: input, indicate the source length, should greater than 0
uint8_t * dest_buf: output, point to the destination
int dest_len: input, indicate the destination length, 
        should be greater or equal than src_len * 2
*/
int ByteStrToHexStr2(const uint8_t * src_buf, int src_len, 
    uint8_t * dest_buf, int dest_len)
{
    if(NULL == src_buf || NULL == dest_buf ||
         src_len <= 0 || dest_len < src_len * 2)
	{
        printf("ByteStrToHexStr input error\n");
        return -1;
    }	
    uint8_t highHex, lowHex;
    const uint8_t * index = src_buf, * end = src_buf + src_len;
    uint8_t * ridx = dest_buf;
    
    while (index < end)
    {
        highHex = (* index) >> 4;
        lowHex = (* index) & 0x0F;
        index ++;

        if (highHex > 0x09)
            highHex += 0x57;
        else
            highHex += 0x30;

        if (lowHex > 0x09)
            lowHex += 0x57;
        else
            lowHex += 0x30;

        *ridx ++ = highHex;
        *ridx ++ = lowHex;
    }
    return 0;
}
