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

#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <fstream>
#include <iostream>
#include <cstdio>

#include <unistd.h>
#include <pwd.h>
#define MAX_PATH FILENAME_MAX

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"
#include "gmp/test.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <signal.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>
#include "wrap.h"

#include <termios.h>

#define SERV_PORT 6666
#define MAX_USERID 1024
#define MAX_FILEID 1024
#define MAX_MSG 4096
#define BUF_SIZE 4096       // APP.cpp、Enclave.edl、Enclave.cpp中使用的数据长度完全一致才行
#define BUF_SIZE_SMALL 4096 // APP.cpp、Enclave.edl、Enclave.cpp中使用的数据长度完全一致才行

#define SEALED_DATA_FILE "sealed_data_blob.txt"

#define SEALED_VK_DATA_FILE "sealed_vk_A_data_blob.txt"
#define SEALED_bListU_DATA_FILE "sealed_bList_U_data_blob.txt"
#define SEALED_keyPairHex_DATA_FILE "sealed_keyPairHex_data_blob.txt"
#define SEALED_shareFileList_DATA_FILE "sealed_shareFileList_data_blob.txt"
#define SEALED_UserRevocationList_DATA_FILE "sealed_UserRevocationList_data_blob.txt"


#define C_PRE_keyPairHex_Backup "c_pre.key"


/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t
{
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED,
     "Unexpected error occurred.",
     NULL},
    {SGX_ERROR_INVALID_PARAMETER,
     "Invalid parameter.",
     NULL},
    {SGX_ERROR_OUT_OF_MEMORY,
     "Out of memory.",
     NULL},
    {SGX_ERROR_ENCLAVE_LOST,
     "Power transition occurred.",
     "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE,
     "Invalid enclave image.",
     NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID,
     "Invalid enclave identification.",
     NULL},
    {SGX_ERROR_INVALID_SIGNATURE,
     "Invalid enclave signature.",
     NULL},
    {SGX_ERROR_OUT_OF_EPC,
     "Out of EPC memory.",
     NULL},
    {SGX_ERROR_NO_DEVICE,
     "Invalid SGX device.",
     "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT,
     "Memory map conflicted.",
     NULL},
    {SGX_ERROR_INVALID_METADATA,
     "Invalid enclave metadata.",
     NULL},
    {SGX_ERROR_DEVICE_BUSY,
     "SGX device was busy.",
     NULL},
    {SGX_ERROR_INVALID_VERSION,
     "Enclave version was invalid.",
     NULL},
    {SGX_ERROR_INVALID_ATTRIBUTE,
     "Enclave was not authorized.",
     NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS,
     "Can't open enclave file.",
     NULL},
    {SGX_ERROR_MEMORY_MAP_FAILURE,
     "Failed to reserve memory for the enclave.",
     NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist / sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++)
    {
        if (ret == sgx_errlist[idx].err)
        {
            if (NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}

void usgx_exit(int reason)
{
    printf("usgx_exit: %d\n", reason);
    exit(reason);
}

int pairing_test2()
{

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    unsigned char data1[BUF_SIZE];
    unsigned char data2[BUF_SIZE];
    size_t len1 = 128;
    size_t len2 = 128;
    printf("===========start t_sgxpbc_call_apis==============\n");

    // char str3[] = "1234567890";
    // sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    // size_t strlen1 = 10;
    // ret = ecall_pointer_size(global_eid, (void*)str3, strlen1);
    // if (ret != SGX_SUCCESS)
    // {
    //     print_error_message(ret);
    //     abort();
    // }

    // printf("\n str3 = %s \n", str3);

    sgx_status_t status = t_sgxpbc_call_apis(global_eid, data1, len1, data2, len2);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_sgxpbc_call_apis has failed.\n");
        return 1; // Test failed
    }
    printf("===========end t_sgxpbc_call_apis==============\n");
    printf("len1 = %d \ndata1=", len1);
    for (int i = 0; i < len1; i++)
    {
        printf("%02x", data1[i]);
    }
    printf("\n len2 = %d \ndata2=", len2);
    for (int i = 0; i < len2; i++)
    {
        printf("%02x", data2[i]);
    }
    printf("\n");

    status = t_sgxpbc_call_test(global_eid, data1, len1, data2, len2);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_sgxpbc_call_test has failed.\n");
        return 1; // Test failed
    }

    status = t_sgxpbc_call_free_pairing(global_eid);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_sgxpbc_call_free_pairing has failed.\n");
        return 1; // Test failed
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("Info: SampleEnclave successfully returned.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}

void printf_key_pair(key_pair_t key_pair)
{
    printf("key_pair: \n");
    printf("\tpk_a: \n");
    printf("\t\tZ_a1: ");
    for (int i = 0; i < sizeof(key_pair.pk_a.Z_a1); i++)
    {
        printf("%02x", key_pair.pk_a.Z_a1[i]);
    }
    printf("\n");
    printf("\t\tg_a2: ");
    for (int i = 0; i < sizeof(key_pair.pk_a.g_a2); i++)
    {
        printf("%02x", key_pair.pk_a.g_a2[i]);
    }
    printf("\n");

    printf("\tsk_a: \n");
    printf("\t\ta1: ");
    for (int i = 0; i < sizeof(key_pair.sk_a.a1); i++)
    {
        printf("%02x", key_pair.sk_a.a1[i]);
    }
    printf("\n");
    printf("\t\ta2: ");
    for (int i = 0; i < sizeof(key_pair.sk_a.a2); i++)
    {
        printf("%02x", key_pair.sk_a.a2[i]);
    }
    printf("\n");
}

void printf_c_a(c_a_t c_a)
{
    printf("c_a: \n");
    printf("\tZ_a1_k:");
    for (int i = 0; i < sizeof(c_a.Z_a1_k); i++)
    {
        printf("%02x", c_a.Z_a1_k[i]);
    }
    printf("\n");

    printf("\tZ_a2_k:");
    for (int i = 0; i < sizeof(c_a.Z_a2_k); i++)
    {
        printf("%02x", c_a.Z_a2_k[i]);
    }
    printf("\n");

    printf("\tm_Z_k:");
    for (int i = 0; i < sizeof(c_a.m_Z_k); i++)
    {
        printf("%02x", c_a.m_Z_k[i]);
    }
    printf("\n");

    printf("\tg_k:");
    for (int i = 0; i < sizeof(c_a.g_k); i++)
    {
        printf("%02x", c_a.g_k[i]);
    }
    printf("\n");

    printf("\tm_Z_a1_k:");
    for (int i = 0; i < sizeof(c_a.m_Z_a1_k); i++)
    {
        printf("%02x", c_a.m_Z_a1_k[i]);
    }
    printf("\n");
}

static size_t get_file_size(const char *filename)
{
    std::ifstream ifs(filename, std::ios::in | std::ios::binary);
    if (!ifs.good())
    {
        printf("Fail to open the file \" %s \"\n", filename);
        return -1;
    }
    ifs.seekg(0, std::ios::end);
    size_t size = (size_t)ifs.tellg();
    return size;
}

static bool read_file_to_buf(const char *filename, uint8_t *buf, size_t bsize)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ifstream ifs(filename, std::ios::binary | std::ios::in);
    if (!ifs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ifs.read(reinterpret_cast<char *>(buf), bsize);
    if (ifs.fail())
    {
        std::cout << "Failed to read the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

static bool write_buf_to_file(const char *filename, const uint8_t *buf, size_t bsize, long offset)
{
    if (filename == NULL || buf == NULL || bsize == 0)
        return false;
    std::ofstream ofs(filename, std::ios::binary | std::ios::out);
    if (!ofs.good())
    {
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
        return false;
    }
    ofs.seekp(offset, std::ios::beg);
    ofs.write(reinterpret_cast<const char *>(buf), bsize);
    if (ofs.fail())
    {
        std::cout << "Failed to write the file \"" << filename << "\"" << std::endl;
        return false;
    }

    return true;
}

static bool remove_file(const char *filename)
{
    if (filename == NULL)
        return false;
    if (std::remove(filename) != 0) {
        std::cout << "Failed to remove the file \"" << filename << "\"" << std::endl;
        return false;
    }
    return true;
}

int c_pre_test()
{
    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    int ret = 0;

    printf("===========start c_pre_main_test==============\n");

    sgx_status_t status = c_pre_main_test(global_eid, &ret);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to c_pre_main_test has failed.\n");
        return 1; // Test failed
    }
    printf("===========end c_pre_main_test==============\n");


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("Info: c_pre_test successfully returned.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}

int pairing_test()
{

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    // printf("===========start t_sgxpbc_pairing_test==============\n");
    // sgx_status_t status1 = t_sgxpbc_pairing_test(global_eid);
    // if (status1 != SGX_SUCCESS)
    // {
    //     print_error_message(status1);
    //     printf("Call to t_sgxpbc_pairing_test has failed.\n");
    //     return 1; // Test failed
    // }
    // return 0;

    printf("===========start t_sgxpbc_pairing_init==============\n");

    sgx_status_t status = t_sgxpbc_pairing_init(global_eid);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_sgxpbc_pairing_init has failed.\n");
        return 1; // Test failed
    }
    printf("===========end t_sgxpbc_pairing_init==============\n");

    status = t_sgxpbc_pairing_generate_g_Z(global_eid);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_sgxpbc_pairing_generate_g_Z has failed.\n");
        return 1; // Test failed
    }
    int ret = 0;
    key_pair_t key_pair_A;
    status = t_Key_Generation(global_eid, &ret,
                              key_pair_A.sk_a.a1, sizeof(key_pair_A.sk_a.a1),
                              key_pair_A.sk_a.a2, sizeof(key_pair_A.sk_a.a2),
                              key_pair_A.pk_a.Z_a1, sizeof(key_pair_A.pk_a.Z_a1),
                              key_pair_A.pk_a.g_a2, sizeof(key_pair_A.pk_a.g_a2));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_Key_Generation has failed.\n");
        return 1; // Test failed
    }
    printf_key_pair(key_pair_A);

    key_pair_t key_pair_B;
    status = t_Key_Generation(global_eid, &ret,
                              key_pair_B.sk_a.a1, sizeof(key_pair_B.sk_a.a1),
                              key_pair_B.sk_a.a2, sizeof(key_pair_B.sk_a.a2),
                              key_pair_B.pk_a.Z_a1, sizeof(key_pair_B.pk_a.Z_a1),
                              key_pair_B.pk_a.g_a2, sizeof(key_pair_B.pk_a.g_a2));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_Key_Generation has failed.\n");
        return 1; // Test failed
    }
    printf_key_pair(key_pair_B);

    printf("*********start t_Re_Encryption_Key_Generation ********\n");

    unsigned char rk_A_B[G1_ELEMENT_LENGTH_IN_BYTES];

    status = t_Re_Encryption_Key_Generation(global_eid, &ret,
                                            key_pair_A.sk_a.a1, sizeof(key_pair_A.sk_a.a1),
                                            key_pair_B.pk_a.g_a2, sizeof(key_pair_B.pk_a.g_a2),
                                            rk_A_B, sizeof(rk_A_B));

    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_Re_Encryption_Key_Generation has failed.\n");
        return 1; // Test failed
    }

    printf("rk_A_B = ");
    for (int i = 0; i < sizeof(rk_A_B); i++)
    {
        printf("%02x", rk_A_B[i]);
    }
    printf("\n");

    printf("*********start t_GetGTRandom ********\n");
    unsigned char m[GT_ELEMENT_LENGTH_IN_BYTES];
    status = t_GetGTRandom(global_eid, &ret, m, GT_ELEMENT_LENGTH_IN_BYTES);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_GetGTRandom has failed.\n");
        return 1; // Test failed
    }
    printf("m = ");
    for (int i = 0; i < sizeof(m); i++)
    {
        printf("%02x", m[i]);
    }
    printf("\n");

    // printf("*********start t_Encryption ********\n");

    c_a_t c_a;

    // status = t_Encryption(global_eid, &ret,
    //     m, sizeof(m),
    //     key_pair_A.pk_a.Z_a1, sizeof(key_pair_A.pk_a.Z_a1),
    //     key_pair_A.sk_a.a2, sizeof(key_pair_A.sk_a.a2),
    //     c_a.Z_a1_k, sizeof(c_a.Z_a1_k),
    //     c_a.m_Z_k, sizeof(c_a.m_Z_k),
    //     c_a.Z_a2_k, sizeof(c_a.Z_a2_k),
    //     c_a.g_k, sizeof(c_a.g_k),
    //     c_a.m_Z_a1_k, sizeof(c_a.m_Z_a1_k)
    //     );
    // if (status != SGX_SUCCESS)
    // {
    //     print_error_message(status);
    //     printf("Call to t_Re_Encryption_Key_Generation has failed.\n");
    //     return 1; // Test failed
    // }
    printf("*********start t_First_Level_Encryption ********\n");
    status = t_First_Level_Encryption(global_eid, &ret,
                                      m, sizeof(m),
                                      key_pair_A.pk_a.Z_a1, sizeof(key_pair_A.pk_a.Z_a1),
                                      key_pair_A.sk_a.a2, sizeof(key_pair_A.sk_a.a2),
                                      c_a.Z_a1_k, sizeof(c_a.Z_a1_k),
                                      c_a.m_Z_k, sizeof(c_a.m_Z_k),
                                      c_a.Z_a2_k, sizeof(c_a.Z_a2_k));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_First_Level_Encryption has failed.\n");
        return 1; // Test failed
    }

    printf_c_a(c_a);

    printf("*********start t_Second_Level_Encryption ********\n");
    status = t_Second_Level_Encryption(global_eid, &ret,
                                       m, sizeof(m),
                                       key_pair_A.pk_a.Z_a1, sizeof(key_pair_A.pk_a.Z_a1),
                                       c_a.g_k, sizeof(c_a.g_k),
                                       c_a.m_Z_a1_k, sizeof(c_a.m_Z_a1_k));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_Second_Level_Encryption has failed.\n");
        return 1; // Test failed
    }

    printf_c_a(c_a);

    printf("*********start t_Re_Encryption ********\n");

    unsigned char Z_b2_a1_k[GT_ELEMENT_LENGTH_IN_BYTES];
    status = t_Re_Encryption(global_eid, &ret,
                             c_a.g_k, sizeof(c_a.g_k),
                             rk_A_B, sizeof(rk_A_B),
                             c_a.m_Z_a1_k, sizeof(c_a.m_Z_a1_k),
                             Z_b2_a1_k, sizeof(Z_b2_a1_k));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_Re_Encryption has failed.\n");
        return 1; // Test failed
    }
    printf("Z_b2_a1_k = ");
    for (int i = 0; i < sizeof(Z_b2_a1_k); i++)
    {
        printf("%02x", Z_b2_a1_k[i]);
    }
    printf("\n");

    printf("*********start t_First_Level_Decryption ********\n");
    status = t_First_Level_Decryption(global_eid, &ret,
                                      c_a.Z_a1_k, sizeof(c_a.Z_a1_k),
                                      c_a.m_Z_k, sizeof(c_a.m_Z_k),
                                      c_a.Z_a2_k, sizeof(c_a.Z_a2_k),
                                      key_pair_A.sk_a.a1, sizeof(key_pair_A.sk_a.a1),
                                      key_pair_A.sk_a.a2, sizeof(key_pair_A.sk_a.a2));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_First_Level_Decryption has failed.\n");
        return 1; // Test failed
    }

    printf("*********start t_Second_Level_Decryption ********\n");
    status = t_Second_Level_Decryption(global_eid, &ret,
                                       c_a.g_k, sizeof(c_a.g_k),
                                       c_a.m_Z_a1_k, sizeof(c_a.m_Z_a1_k),
                                       key_pair_A.sk_a.a1, sizeof(key_pair_A.sk_a.a1));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_First_Level_Decryption has failed.\n");
        return 1; // Test failed
    }

    printf("*********start t_B_Decryption ********\n");
    status = t_B_Decryption(global_eid, &ret,
                            c_a.m_Z_a1_k, sizeof(c_a.m_Z_a1_k),
                            Z_b2_a1_k, sizeof(Z_b2_a1_k),
                            key_pair_B.sk_a.a2, sizeof(key_pair_B.sk_a.a2));
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_B_Decryption has failed.\n");
        return 1; // Test failed
    }

    status = t_sgxpbc_pairing_destroy(global_eid);
    if (status != SGX_SUCCESS)
    {
        print_error_message(status);
        printf("Call to t_sgxpbc_pairing_destroy has failed.\n");
        return 1; // Test failed
    }

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("Info: SampleEnclave successfully returned.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}

bool seal_test()
{
    // Load the enclave for sealing
    sgx_status_t ret;
    if (initialize_enclave() < 0)
    {
        print_error_message(ret);
        return false;
    }

    // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = get_sealed_data_size(global_eid, &sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        sgx_destroy_enclave(global_eid);
        return false;
    }

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(global_eid);
        return false;
    }
    sgx_status_t retval;
    ret = seal_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        free(temp_sealed_buf);
        sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        free(temp_sealed_buf);
        sgx_destroy_enclave(global_eid);
        return false;
    }

    if (write_buf_to_file(SEALED_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        std::cout << "Failed to save the sealed data blob to \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_sealed_buf);
        sgx_destroy_enclave(global_eid);
        return false;
    }

    free(temp_sealed_buf);
    sgx_destroy_enclave(global_eid);

    std::cout << "Sealing data succeeded." << std::endl;

    return true;
}

bool unseal_test()
{

    sgx_status_t ret;
    if (initialize_enclave() < 0)
    {
        print_error_message(ret);
        return false;
    }

    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        std::cout << "Failed to get the file size of \"" << SEALED_DATA_FILE << "\"" << std::endl;
        sgx_destroy_enclave(global_eid);
        return false;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if (temp_buf == NULL)
    {
        std::cout << "Out of memory" << std::endl;
        sgx_destroy_enclave(global_eid);
        return false;
    }
    if (read_file_to_buf(SEALED_DATA_FILE, temp_buf, fsize) == false)
    {
        std::cout << "Failed to read the sealed data blob from \"" << SEALED_DATA_FILE << "\"" << std::endl;
        free(temp_buf);
        sgx_destroy_enclave(global_eid);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t retval;
    ret = unseal_data(global_eid, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        free(temp_buf);
        sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        free(temp_buf);
        sgx_destroy_enclave(global_eid);
        return false;
    }

    free(temp_buf);
    sgx_destroy_enclave(global_eid);

    std::cout << "Unseal succeeded." << std::endl;
    return true;
}

bool loadSealed_Vk_Data() {

    sgx_status_t ret;

    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_VK_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        printf("Failed to get the file size of \" %s \"\n", SEALED_VK_DATA_FILE);
        printf("no sealed vk data need to load\n");
        // sgx_destroy_enclave(global_eid);
        return true;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if (temp_buf == NULL)
    {
        printf("Out of memory\n");
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    if (read_file_to_buf(SEALED_VK_DATA_FILE, temp_buf, fsize) == false)
    {
        printf("Failed to read the sealed vk data blob from \" %s \"\n");
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }

    // Unseal the sealed blob
    sgx_status_t retval;
    ret = t_unseal_vk_A_data(global_eid, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }

    free(temp_buf);

    printf("Unseal vk succeeded.\n");
    return true;
}

bool loadSealed_bList_U_Data() {

    sgx_status_t ret;

    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_bListU_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        printf("Failed to get the file size of \" %s \"\n", SEALED_bListU_DATA_FILE);
        printf("no sealed bList_U data need to load\n");
        // sgx_destroy_enclave(global_eid);
        return true;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if (temp_buf == NULL)
    {
        printf("Out of memory\n");
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    if (read_file_to_buf(SEALED_bListU_DATA_FILE, temp_buf, fsize) == false)
    {
        printf("Failed to read the sealed bList_U data blob from \" %s \"\n");
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    // Unseal the sealed blob
    sgx_status_t retval;
    ret = unseal_bList_U_data(global_eid, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        printf("call unseal_bList_U_data ret error\n");
        print_error_message(ret);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        printf("call unseal_bList_U_data retval error\n");
        print_error_message(retval);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }

    free(temp_buf);

    printf("Unseal bList_U succeeded.\n");
    return true;
}

bool loadSealed_keyPairHex_Data() {

    sgx_status_t ret;

    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_keyPairHex_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        printf("Failed to get the file size of \" %s \"\n", SEALED_keyPairHex_DATA_FILE);
        printf("no sealed keyPairHe data need to load\n");
        // sgx_destroy_enclave(global_eid);
        return true;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if (temp_buf == NULL)
    {
        printf("Out of memory\n");
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    if (read_file_to_buf(SEALED_keyPairHex_DATA_FILE, temp_buf, fsize) == false)
    {
        printf("Failed to read the sealed keyPair data blob from \" %s \"\n");
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    // Unseal the sealed blob
    sgx_status_t retval;
    ret = t_unseal_keyPairHex_data(global_eid, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        printf("call t_unseal_keyPairHex_data ret error\n");
        print_error_message(ret);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        printf("call t_unseal_keyPairHex_data retval error\n");
        print_error_message(retval);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }

    free(temp_buf);

    printf("Unseal keyPairHex succeeded.\n");
    return true;
}


bool loadSealed_shareFileList_Data() {

    sgx_status_t ret;

    // Read the sealed blob from the file
    size_t fsize = get_file_size(SEALED_shareFileList_DATA_FILE);
    if (fsize == (size_t)-1)
    {
        printf("Failed to get the file size of \" %s \"\n", SEALED_shareFileList_DATA_FILE);
        printf("no sealed shareFileList data need to load\n");
        // sgx_destroy_enclave(global_eid);
        return true;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if (temp_buf == NULL)
    {
        printf("Out of memory\n");
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    if (read_file_to_buf(SEALED_shareFileList_DATA_FILE, temp_buf, fsize) == false)
    {
        printf("Failed to read the sealed shareFileList data blob from \" %s \"\n");
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    // Unseal the sealed blob
    sgx_status_t retval;
    ret = t_unseal_shareFileList_data(global_eid, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        printf("call t_unseal_shareFileList_data ret error\n");
        print_error_message(ret);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        printf("call t_unseal_shareFileList_data retval error\n");
        print_error_message(retval);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }

    free(temp_buf);

    printf("Unseal shareFileList succeeded.\n");
    return true;
}

bool loadSealed_UserRevocationList_Data() {

    sgx_status_t ret;

    // Read the sealed blob from the file
    printf("debug 1\n");
    size_t fsize = get_file_size(SEALED_UserRevocationList_DATA_FILE);
    printf("fsize is %d\n", fsize);
    if (fsize == (size_t)-1)
    {
        printf("Failed to get the file size of \" %s \"\n", SEALED_UserRevocationList_DATA_FILE);
        printf("no sealed UserRevocationList data need to load\n");
        // sgx_destroy_enclave(global_eid);
        return true;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if (temp_buf == NULL)
    {
        printf("Out of memory\n");
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    if (read_file_to_buf(SEALED_UserRevocationList_DATA_FILE, temp_buf, fsize) == false)
    {
        printf("Failed to read the sealed UserRevocationList data blob from \" %s \"\n");
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    // Unseal the sealed blob
    sgx_status_t retval;
    ret = t_unseal_UserRevocationList_data(global_eid, &retval, temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        printf("call t_unseal_UserRevocationList_data ret error\n");
        print_error_message(ret);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    else if (retval != SGX_SUCCESS)
    {
        printf("call t_unseal_UserRevocationList_data retval error\n");
        print_error_message(retval);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }

    free(temp_buf);

    printf("Unseal UserRevocationList succeeded.\n");
    return true;
}

bool loadSealedData() {
    bool b = false;
    b = loadSealed_Vk_Data();
    if(!b) {
        printf("loadSealed_Vk_Data error\n");
        return false;
    }
    // loadSealed_bList_U_Data();
    b = loadSealed_keyPairHex_Data();
    if(!b) {
        printf("loadSealed_keyPairHex_Data error\n");
        return false;
    }
    b = loadSealed_shareFileList_Data();
    if(!b) {
        printf("loadSealed_shareFileList_Data error\n");
        return false;
    }
    b = loadSealed_UserRevocationList_Data();
    if(!b) {
        printf("loadSealed_UserRevocationList_Data error\n");
        return false;
    }

    return true;
}


void ssl_test()
{
    // Load the enclave for sealing
    sgx_status_t ret;
    if (initialize_enclave() < 0)
    {
        print_error_message(ret);
        return;
    }

    ret = t_sgxssl_test(global_eid);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        sgx_destroy_enclave(global_eid);
        return;
    }

    ret = t_sgxssl_ecdsa_test(global_eid);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        sgx_destroy_enclave(global_eid);
        return;
    }

    sgx_destroy_enclave(global_eid);

    std::cout << "Sealing data succeeded." << std::endl;

    return;
}

void get_password(char *password)
{
    static struct termios old_terminal;
    static struct termios new_terminal;

    //get settings of the actual terminal
    tcgetattr(STDIN_FILENO, &old_terminal);

    // do not echo the characters
    new_terminal = old_terminal;
    new_terminal.c_lflag &= ~(ECHO);

    // set this as the new terminal options
    tcsetattr(STDIN_FILENO, TCSANOW, &new_terminal);

    // get the password
    // the user can add chars and delete if he puts it wrong
    // the input process is done when he hits the enter
    // the \n is stored, we replace it with \0
    if (fgets(password, BUFSIZ, stdin) == NULL)
        password[0] = '\0';
    else
        password[strlen(password)-1] = '\0';

    // go back to the old settings
    tcsetattr(STDIN_FILENO, TCSANOW, &old_terminal);
}

int exportKey() {
    bool b = false;
    // loadSealed_bList_U_Data();
    b = loadSealed_keyPairHex_Data();
    if(!b) {
        printf("loadSealed_Vk_Data error\n");
        return -1;
    }

    char password[BUFSIZ];
    char password2[BUFSIZ];

    puts("input password:");
    get_password(password);
    puts("input password again:");
    get_password(password2);
    puts(password);
    puts(password2);
    int result = strcmp(password, password2);
    if(result == 0) {
        printf("input same\n");
    } else {
        printf("input not same\n");
        return -1;
    }
    uint8_t encKeyPair[BUFSIZ];
    int32_t encKeyPair_len = 0;
    sgx_status_t ret = t_export_keyPairHex(global_eid, &encKeyPair_len, 
        (uint8_t *)password, strlen(password),
        encKeyPair, BUFSIZ);
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_export_keyPairHex failed.\n");
        print_error_message(ret);
        return -2;
    }
    else if (encKeyPair_len < 0)
    {
        printf("t_export_keyPairHex return error, encKeyPair_len is %d.\n", encKeyPair_len);
        return -2;
    }
    printf("Call t_export_keyPairHex success. encKeyPair_len = %d\n", encKeyPair_len);

    if (write_buf_to_file(C_PRE_keyPairHex_Backup, encKeyPair, encKeyPair_len, 0) == false)
    {
        printf("Failed to save the sealed data blob to \" %s \" \n", C_PRE_keyPairHex_Backup);
        return -2;
    }

    printf("write_buf_to_file success.\n");
    return 0;
}

int importKey() {
    char password[BUFSIZ];
    puts("input password:");
    get_password(password);
    puts(password);

    // Read the sealed blob from the file
    size_t fsize = get_file_size(C_PRE_keyPairHex_Backup);
    if (fsize == (size_t)-1)
    {
        printf("Failed to get the file size of \" %s \"\n", C_PRE_keyPairHex_Backup);
        printf("no keyPairHex could import\n");
        // sgx_destroy_enclave(global_eid);
        return -1;
    }
    uint8_t *temp_buf = (uint8_t *)malloc(fsize);
    if (temp_buf == NULL)
    {
        printf("Out of memory\n");
        // sgx_destroy_enclave(global_eid);
        return -1;
    }
    if (read_file_to_buf(C_PRE_keyPairHex_Backup, temp_buf, fsize) == false)
    {
        printf("Failed to read the keyPairBackup from \" %s \"\n", C_PRE_keyPairHex_Backup);
        free(temp_buf);
        // sgx_destroy_enclave(global_eid);
        return false;
    }
    printf("read %d bytes from \" %s \"\n", fsize, C_PRE_keyPairHex_Backup);
    for(int i=0;i<fsize;i++) {
        printf("%c", temp_buf[i]);
    }
    printf("\n");
    int32_t iret;
    sgx_status_t ret = t_import_keyPairHex(global_eid, &iret, 
        (uint8_t *)password, strlen(password),
        temp_buf, fsize);
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_import_keyPairHex failed.\n");
        print_error_message(ret);
        return -2;
    }
    else if (iret < 0)
    {
        printf("t_import_keyPairHex return error, iret is %d.\n", iret);
        return -2;
    }
    printf("Call t_import_keyPairHex success. iret is %d\n", iret);

    /*
    seal keyPairHex data
    */
   // Get the sealed data size
    uint32_t sealed_data_size = 0;
    ret = t_get_sealed_keyPairHex_data_size(global_eid, &sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        printf("t_get_sealed_keyPairHex_data_size return error, ret is %d.\n", ret);
        return -3;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        printf("t_get_sealed_keyPairHex_data_size out of memory.\n");
        return -3;
    }

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
    {
        printf("Out of memory\n");
        return -2;
    }
    sgx_status_t retval;
    ret = t_seal_keyPairHex_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        free(temp_sealed_buf);
        printf("t_seal_keyPairHex_data return error %d\n", ret);
        return -3;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        free(temp_sealed_buf);
        printf("t_seal_keyPairHex_data return error retval = %d\n", retval);
        return -3;
    }

    if (write_buf_to_file(SEALED_keyPairHex_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        printf("Failed to save the sealed data blob to \" %s \" \n", SEALED_keyPairHex_DATA_FILE);
        free(temp_sealed_buf);
        return -2;
    }

    free(temp_sealed_buf);
    printf("Sealing data succeeded.\n");

    return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    printf("*******\n");
    // pairing_test();
    // seal_test();
    // unseal_test();
    // c_pre_test();
    // ssl_test();

    /* Initialize the enclave , set global_eid*/
    if (initialize_enclave() < 0)
    {
        printf("initialize_enclave error, Enter a character before exit ...\n");
        return -2;
    }

    if(argc >= 2) {
        if(strcmp(argv[1], "exportKey") == 0) {
            printf("exportKey\n");
            exportKey();
        } else if (strcmp(argv[1], "importKey") == 0) {
            printf("importKey\n");
            importKey();
        } else {
            printf("unknown argument\n");
        }
        sgx_destroy_enclave(global_eid);
        return 0;
    }

    bool b = loadSealedData();
    if(!b) {
        printf("loadSealedData error\n");
        sgx_destroy_enclave(global_eid);
        return -1;
    }

    // Initialize listener
    int i, j, n, nready;

    int maxfd = 0;

    int listenfd, connfd;

    char buf[BUFSIZ]; /*#defineINET_ADDRSTRLEN16*/
    char user_id[MAX_USERID];
    char file_id[MAX_FILEID];
    unsigned char msg[BUFSIZ];
    memset(user_id, 0x00, sizeof(user_id));
    memset(file_id, 0x00, sizeof(file_id));
    memset(msg, 0x00, sizeof(msg));

    struct sockaddr_in clie_addr, serv_addr;
    socklen_t clie_addr_len;

    listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(SERV_PORT);
    Bind(listenfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    Listen(listenfd, 128);

    fd_set rset, allset; /*rset读事件文件描述符集合allset用来暂存*/

    maxfd = listenfd;

    FD_ZERO(&allset);
    FD_SET(listenfd, &allset); /*构造select监控文件描述符集*/

    printf("======waiting for client's request======\n");
    fflush(stdout);

    while (1)
    {
        rset = allset; /*每次循环时都从新设置select监控信号集*/
        nready = select(maxfd + 1, &rset, NULL, NULL, NULL);
        if (nready < 0)
            perr_exit("select error");

        if (FD_ISSET(listenfd, &rset))
        { /*说明有新的客户端链接请求*/

            clie_addr_len = sizeof(clie_addr);
            connfd = Accept(listenfd, (struct sockaddr *)&clie_addr, &clie_addr_len); /*Accept不会阻塞*/

            FD_SET(connfd, &allset); /*向监控文件描述符集合allset添加新的文件描述符connfd*/

            printf("new client. fd:%d\n", connfd);

            if (maxfd < connfd)
                maxfd = connfd;

            if (0 == --nready) /*只有listenfd有事件,后续的for不需执行*/
                continue;
        }

        for (i = listenfd + 1; i <= maxfd; i++)
        { /*检测哪个clients有数据就绪*/

            if (FD_ISSET(i, &rset))
            {
                memset(msg, 0x00, sizeof(msg));
                if ((n = Read(i, msg, sizeof(msg))) == 0)
                { /*当client关闭链接时,服务器端也关闭对应链接*/
                    printf("client %d has disconnected!\n", i);
                    Close(i);
                    FD_CLR(i, &allset); /*解除select对此文件描述符的监控*/
                }
                else if (n > 0)
                {
#ifdef PRINT_DEBUG_INFO
                    printf("recvMsg is :\n");
                    dump_hex(msg, n, 16);
#endif
                    unsigned char responseMsg[BUFSIZ];
                    size_t responseMsgLen;

                    handleRequest(msg, n, i, responseMsg, &responseMsgLen);

                    if(responseMsgLen > 0) 
                    {
#ifdef PRINT_DEBUG_INFO
                        printf("responseMsg is :\n");
                        dump_hex(responseMsg, responseMsgLen, 16);
#endif
                        Write(i, responseMsg, responseMsgLen);
                    }
                    fflush(stdout);
                    // memset(user_id, 0x00, sizeof(user_id));
                    // memset(file_id, 0x00, sizeof(file_id));
                    // sscanf(msg, "%s %s", user_id, file_id);
                    // printf("receiving a request(%s %s)\n", user_id, file_id);

                    // todo something with enclave
                    // access_control(user_id, file_id);
                    // strcpy(buf, "get file");
                    // Write(i, buf, strlen(buf));

                    // access_control_file(i, user_id, file_id);
                }
            }
        }
    }

    Close(listenfd);
    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    // end ====
}


int packResp(unsigned char *code, size_t codeLen, 
    unsigned char *msg, size_t msgLen,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    int offset = 0;
    memcpy(responseMsg + offset, code, codeLen);
    offset += codeLen;
    sprintf((char *)(responseMsg + offset), "%04d", msgLen);
    offset += 4;
    memcpy(responseMsg + offset, msg, msgLen);
    offset += msgLen;
    (*p_responseMsgLength) = offset;
    return 0;
}

int handleRequest(unsigned char *requestMsg, size_t requestMsgLen, int fd, 
        unsigned char *responseMsg, size_t *p_responseMsgLen) {
    unsigned char requestCode[5];
    char requestBodyLengthStr[5];
    size_t requestBodyLength, responseBodyLength;
    memset(requestCode, 0x00, sizeof(requestCode));
    memset(requestBodyLengthStr, 0x00, sizeof(requestBodyLengthStr));
    int offset = 0;
    if(requestMsgLen < 8) {
        char errMsg[BUFSIZ];
        responseBodyLength = sprintf(errMsg, "error request msg, len is %d, less than 4.", requestMsgLen);
        memset(responseMsg, 0x00, sizeof(responseMsg));
        offset = 0;
        memcpy(responseMsg + offset, "0001", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", responseBodyLength);
        offset += 4;
        memcpy(responseMsg + offset, errMsg, responseBodyLength);
        offset += responseBodyLength;
        (*p_responseMsgLen) = offset;
        // printf("responseMsg is : %s\n", responseMsg);
        // Write(fd, responseMsg, offset);
        return -1;
    }

    memcpy(requestCode, requestMsg, 4);
    memcpy(requestBodyLengthStr, requestMsg + 4, 4);
    requestBodyLength = atoi(requestBodyLengthStr);
    if(requestBodyLength <= 0)
    {
        char errMsg[BUFSIZ];
        responseBodyLength = sprintf("error body length, requestBodyLengthStr is %s, bodyLength is %d \n", 
            requestBodyLengthStr,
            requestBodyLength);
        memset(responseMsg, 0x00, sizeof(responseMsg));
        offset = 0;
        memcpy(responseMsg + offset, "0002", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", responseBodyLength);
        offset += 4;
        memcpy(responseMsg + offset, errMsg, responseBodyLength);
        offset += responseBodyLength;
        (*p_responseMsgLen) = offset;
        return -1;
    }

    unsigned char requestBody[BUFSIZ];
    unsigned char responseBody[BUFSIZ];
    memset(requestBody, 0x00, sizeof(requestBody));
    memset(responseBody, 0x00, sizeof(responseBody));
    memcpy(requestBody, requestMsg + 4 + 4, requestBodyLength);
    printf("request code: %s\n", requestCode);
    int iret = -1;
    if(memcmp(requestCode, "0001", 4) == 0) {
        // memset(responseBody, 0x00, sizeof(responseBody));
        memset(responseMsg, 0x00, sizeof(responseMsg));
        iret = handleRequest0001(requestBody, requestBodyLength, 
            responseMsg, p_responseMsgLen);
        // if(iret < 0) {
        //     memcpy(responseMsg, "0101", 4);
        //     offset += 4;
        //     sprintf((char *)(responseMsg + offset), "%04d", responseBodyLength);
        //     offset += 4;
        //     memcpy(responseMsg + offset, responseBody, responseBodyLength);
        //     offset += responseBodyLength;
        //     (*p_responseMsgLen) = offset;
        // } 
        // else {
        //     memcpy(responseMsg, "00000000", 8);
        //     (*p_responseMsgLen) = 8;
        // }
        
        
        // printf("responseMsg is : %s\n", responseMsg);
        // Write(fd, responseMsg, offset);
    } 
    else if(memcmp(requestCode, "0002", 4) == 0) {
        memset(responseBody, 0x00, sizeof(responseBody));
        memset(responseMsg, 0x00, sizeof(responseMsg));
        iret = handleRequest0002(requestBody, requestBodyLength, 
            responseMsg, p_responseMsgLen);
        
        // printf("responseMsg is : %s\n", responseMsg);
        // Write(fd, responseMsg, offset);
    }
    else if(memcmp(requestCode, "0003", 4) == 0) {
        memset(responseBody, 0x00, sizeof(responseBody));
        memset(responseMsg, 0x00, sizeof(responseMsg));
        iret = handleRequest0003(requestBody, requestBodyLength, 
            responseMsg, p_responseMsgLen);
        
        // printf("responseMsg is : %s\n", responseMsg);
        // Write(fd, responseMsg, offset);
    }
    else if(memcmp(requestCode, "0004", 4) == 0) {
        memset(responseBody, 0x00, sizeof(responseBody));
        memset(responseMsg, 0x00, sizeof(responseMsg));
        iret = handleRequest0004(requestBody, requestBodyLength, 
            responseMsg, p_responseMsgLen);
        
        // printf("responseMsg is : %s\n", responseMsg);
        // Write(fd, responseMsg, offset);
    } 
    else if(memcmp(requestCode, "0005", 4) == 0) {
        memset(responseBody, 0x00, sizeof(responseBody));
        memset(responseMsg, 0x00, sizeof(responseMsg));
        iret = handleRequest0005(requestBody, requestBodyLength, 
            responseMsg, p_responseMsgLen);
        
        // printf("responseMsg is : %s\n", responseMsg);
        // Write(fd, responseMsg, offset);
    } 
    else if(memcmp(requestCode, "1001", 4) == 0) {
        memset(responseBody, 0x00, sizeof(responseBody));
        memset(responseMsg, 0x00, sizeof(responseMsg));
        iret = handleRequest1001(requestBody, requestBodyLength, 
            responseMsg, p_responseMsgLen);
        
    }
    else if(memcmp(requestCode, "1002", 4) == 0) {
        memset(responseBody, 0x00, sizeof(responseBody));
        memset(responseMsg, 0x00, sizeof(responseMsg));
        iret = handleRequest1002(requestBody, requestBodyLength, 
            responseMsg, p_responseMsgLen);
    }
    else {
        char errMsg[BUFSIZ];
        responseBodyLength = sprintf(errMsg, "error request msg, unknown request code: %s\n", requestCode);
        memset(responseMsg, 0x00, sizeof(responseMsg));
        offset = 0;
        memcpy(responseMsg + offset, "0003", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", responseBodyLength);
        offset += 4;
        memcpy(responseMsg + offset, errMsg, responseBodyLength);
        offset += responseBodyLength;
        (*p_responseMsgLen) = offset;
    }

    return iret;
}
    
int handleRequest0001(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    
    /*
    input:
    userid Length(4 bytes) + userid(<=20 bytes) +
    verify key(vk) Length(4 bytes) + verify key(vk)(<=256 bytes)
    */
   
   size_t userIdLength, vk_A_Length;
   char userIdLengthStr[5];
   char vk_A_LengthStr[5];
   unsigned char userId[20];
   unsigned char vk_A[BUFSIZ];
   int offset = 0;
   memset(userIdLengthStr, 0x00, sizeof(userIdLengthStr));
   memcpy(userIdLengthStr, requestBody, 4);
   userIdLength = atoi(userIdLengthStr);
   if(userIdLength <= 0 || userIdLength > sizeof(userId))
    {
        printf("error userId length, userId is %d \n", userIdLength);
        int len = strlen(ERRORMSG_REQUEST_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0101", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_REQUEST_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -1;
    }
    memcpy(userId, requestBody + 4, userIdLength);

    memset(vk_A_LengthStr, 0x00, sizeof(vk_A_LengthStr));
    memcpy(vk_A_LengthStr, requestBody + 4 + userIdLength, 4);
    vk_A_Length = atoi(vk_A_LengthStr);
    if(vk_A_Length <= 0 || vk_A_Length > sizeof(vk_A))
    {
        printf("error vk_A length, vk_A_Length is %d \n", vk_A_Length);
        int len = strlen(ERRORMSG_REQUEST_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0101", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_REQUEST_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -1;
    }
    memcpy(vk_A, requestBody + 4 + userIdLength + 4, vk_A_Length);
#ifdef PRINT_DEBUG_INFO
    printf("userIdLength is %d, userId is :\n", userIdLength);
    dump_hex(userId, userIdLength, 16);
    printf("vk_A_Length is %d, vk_A is :\n", vk_A_Length);
    dump_hex(vk_A, vk_A_Length, 16);
#endif
    sgx_status_t retval;

#ifdef TIME_COST
    struct timespec start, end;
    long long elapsedTime;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    sgx_status_t ret = t_Admin_Setting(global_eid, &retval, vk_A, vk_A_Length);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsedTime = (end.tv_sec - start.tv_sec) * 1000000000l + (end.tv_nsec - start.tv_nsec);
    printf("t_Admin_Setting Elapsed time: %ld nanoseconds\n", elapsedTime);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_Admin_Setting failed.\n");
        print_error_message(ret);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0102", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0102", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }

    /*
    seal vk_A data
    */
   // Get the sealed data size
    uint32_t sealed_data_size = 0;
#ifdef TIME_COST
    struct timespec start_getSealSize, end_getSealSize;
    long long elapsedTime_getSealSize;
    clock_gettime(CLOCK_MONOTONIC, &start_getSealSize);
#endif
    ret = t_get_sealed_vk_A_data_size(global_eid, &sealed_data_size);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end_getSealSize);
    elapsedTime_getSealSize = (end_getSealSize.tv_sec - start_getSealSize.tv_sec) * 1000000000l + 
        (end_getSealSize.tv_nsec - start_getSealSize.tv_nsec);
    printf("t_get_sealed_vk_A_data_size Elapsed time: %ld nanoseconds\n", elapsedTime_getSealSize);
#endif
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        // sgx_destroy_enclave(global_eid);
        printf("sealed_data_size equal to %ld.\n", UINT32_MAX);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
    {
        printf("Out of memory\n");
        int len = strlen(ERRORMSG_MEMORY_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_MEMORY_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }
#ifdef TIME_COST
    struct timespec start_Seal, end_Seal;
    long long elapsedTime_Seal;
    clock_gettime(CLOCK_MONOTONIC, &start_Seal);
#endif
    ret = t_seal_vk_A_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end_Seal);
    elapsedTime_Seal = (end_Seal.tv_sec - start_Seal.tv_sec) * 1000000000l + 
        (end_Seal.tv_nsec - start_Seal.tv_nsec);
    printf("t_seal_vk_A_data Elapsed time: %ld nanoseconds\n", elapsedTime_Seal);
#endif
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        free(temp_sealed_buf);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        free(temp_sealed_buf);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }

    if (write_buf_to_file(SEALED_VK_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        printf("Failed to save the sealed data blob to \" %s \" \n", SEALED_VK_DATA_FILE);
        free(temp_sealed_buf);
        int len = strlen(ERRORMSG_FILE_IO_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0104", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_FILE_IO_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }

    free(temp_sealed_buf);
    printf("Sealing data succeeded.\n");
    // set successful respond
    memcpy(responseMsg, "00000000", 8);
    (*p_responseMsgLength) = 8;
    printf("handleRequest0001 succeeded.\n");
    return 0;
}

int handleRequest0002(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    
    /*
    input:
    userid Length(4 bytes) + userid(<=20 bytes)
    */
   
   size_t userIdLength;
   char userIdLengthStr[5];
   unsigned char userId[20];
   int offset = 0;

   memset(userIdLengthStr, 0x00, sizeof(userIdLengthStr));
   memcpy(userIdLengthStr, requestBody, 4);
   userIdLength = atoi(userIdLengthStr);
   if(userIdLength <= 0 || userIdLength > sizeof(userId))
    {
        printf("error userId length, userId is %d \n", userIdLength);
        int len = strlen(ERRORMSG_REQUEST_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0101", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_REQUEST_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -1;
    }
    memcpy(userId, requestBody + 4, userIdLength);
#ifdef PRINT_DEBUG_INFO
    printf("userIdLength is %d, userId is :\n", userIdLength);
    dump_hex(userId, userIdLength, 16);
#endif
    sgx_status_t retval;
    unsigned char ek_TEE[G1_ELEMENT_LENGTH_IN_BYTES * 2];
#ifdef TIME_COST
    struct timespec start, end;
    long long elapsedTime;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    sgx_status_t ret = t_Trusted_Setup(global_eid, &retval, ek_TEE, sizeof(ek_TEE));
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsedTime = (end.tv_sec - start.tv_sec) * 1000000000l + (end.tv_nsec - start.tv_nsec);
    printf("t_Trusted_Setup Elapsed time: %ld nanoseconds\n", elapsedTime);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_Trusted_Setup failed.\n");
        print_error_message(ret);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }

    /*
    seal keyPairHex data
    */
   // Get the sealed data size
    uint32_t sealed_data_size = 0;
#ifdef TIME_COST
    struct timespec start_getSealSize, end_getSealSize;
    long long elapsedTime_getSealSize;
    clock_gettime(CLOCK_MONOTONIC, &start_getSealSize);
#endif
    ret = t_get_sealed_keyPairHex_data_size(global_eid, &sealed_data_size);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end_getSealSize);
    elapsedTime_getSealSize = (end_getSealSize.tv_sec - start_getSealSize.tv_sec) * 1000000000l + 
        (end_getSealSize.tv_nsec - start_getSealSize.tv_nsec);
    printf("t_get_sealed_keyPairHex_data_size Elapsed time: %ld nanoseconds\n", elapsedTime_getSealSize);
#endif
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }

    uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
    if (temp_sealed_buf == NULL)
    {
        printf("Out of memory\n");
        int len = strlen(ERRORMSG_MEMORY_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0102", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_MEMORY_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }
#ifdef TIME_COST
    struct timespec start_Seal, end_Seal;
    long long elapsedTime_Seal;
    clock_gettime(CLOCK_MONOTONIC, &start_Seal);
#endif
    ret = t_seal_keyPairHex_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end_Seal);
    elapsedTime_Seal = (end_Seal.tv_sec - start_Seal.tv_sec) * 1000000000l + 
        (end_Seal.tv_nsec - start_Seal.tv_nsec);
    printf("t_seal_keyPairHex_data Elapsed time: %ld nanoseconds\n", elapsedTime_Seal);
#endif
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        free(temp_sealed_buf);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        free(temp_sealed_buf);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -3;
    }

    if (write_buf_to_file(SEALED_keyPairHex_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
    {
        printf("Failed to save the sealed data blob to \" %s \" \n", SEALED_keyPairHex_DATA_FILE);
        free(temp_sealed_buf);
        int len = strlen(ERRORMSG_FILE_IO_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0104", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_FILE_IO_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }

    free(temp_sealed_buf);
    printf("Sealing data succeeded.\n");

    // sgx_destroy_enclave(global_eid);
    // add return msg
    offset = 0;
    memcpy(responseMsg + offset, "0000", 4);
    offset += 4;
    sprintf((char *)(responseMsg + offset), "%04d", (sizeof(ek_TEE) + 4));
    offset += 4;
    sprintf((char *)(responseMsg + offset), "%04d", sizeof(ek_TEE));
    offset += 4;
    memcpy(responseMsg + offset, ek_TEE, sizeof(ek_TEE));
    offset += sizeof(ek_TEE);
    (*p_responseMsgLength) = offset;

    printf("handleRequest0002 succeeded.\n");
    return 0;
}


int handleRequest0003(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    
    /*
    ownerUserIdLength(4 bytes) + ownerUserId(20 bytes) + 
    sharedWithUserIdLength(4 bytes) + shareWithUserId(20 bytes) +
    shareIdLength(4 bytes) + shareId(50 bytes) +
    fileIdLength(4 bytes) + fileId(50 bytes) + 
    filenameLength(4 bytes) + filename(256 bytes) + 
    C_rk_length(4 bytes) + C_rk(568 bytes) + 
    CDEK_rk_C1_length(4 bytes) +  CDEK_rk_C1(256 bytes) + 
    CDEK_rk_C2_length(4 bytes) +  CDEK_rk_C2(256 bytes) + 
    CDEK_rk_C3_length(4 bytes) +  CDEK_rk_C3(512 bytes) + 
    CDEK_rk_C4_length(4 bytes) +  CDEK_rk_C4(256 bytes) + 
    Cert_owner_infoLength(4 bytes) + Cert_owner_info(600 bytes) +  
    Cert_owner_info_sign_valueLength(4 bytes) + Cert_owner_info_sign_value(256 bytes) + 
    owner_grant_infoLength(4 bytes) + owner_grant_info(2144 bytes) + 
    owner_grant_info_sign_valueLength(4 bytes) + owner_grant_info_sign_value(256 bytes) +
    C_DEK_C1_length(4 bytes) +  C_DEK_C1(256 bytes) +
    C_DEK_C2_length(4 bytes) +  C_DEK_C2(256 bytes) +
    C_DEK_C3_length(4 bytes) +  C_DEK_C3(512 bytes) +
    C_DEK_C4_length(4 bytes) +  C_DEK_C4(256 bytes)

    */
   
   size_t ownerUserIdLength, sharedWithUserIdLength, shareIdLength, fileIdLength, filenameLength,C_rk_length;
   size_t CDEK_rk_C1_length, CDEK_rk_C2_length, CDEK_rk_C3_length, CDEK_rk_C4_length;
   size_t Cert_owner_infoLength, Cert_owner_info_sign_valueLength;
   size_t owner_grant_infoLength, owner_grant_info_sign_valueLength;
   size_t C_DEK_C1_length, C_DEK_C2_length, C_DEK_C3_length, C_DEK_C4_length;

   char ownerUserIdLengthStr[5];
   char sharedWithUserIdLengthStr[5];
   char shareIdLengthStr[5];
   char fileIdLengthStr[5];
   char filenameLengthStr[5];
   char C_rk_lengthStr[5];
   char CDEK_rk_C1_lengthStr[5];
   char CDEK_rk_C2_lengthStr[5];
   char CDEK_rk_C3_lengthStr[5];
   char CDEK_rk_C4_lengthStr[5];
   char Cert_owner_infoLengthStr[5];
   char Cert_owner_info_sign_valueLengthStr[5];
   char owner_grant_infoLengthStr[5];
   char owner_grant_info_sign_valueLengthStr[5];
   char C_DEK_C1_lengthStr[5];
   char C_DEK_C2_lengthStr[5];
   char C_DEK_C3_lengthStr[5];
   char C_DEK_C4_lengthStr[5];

   unsigned char ownerUserId[20];
   unsigned char sharedWithUserId[20];
   unsigned char shareId[50];
   unsigned char fileId[50];
   unsigned char filename[256];
   unsigned char C_rk[568];
   unsigned char CDEK_rk_C1[256];
   unsigned char CDEK_rk_C2[256];
   unsigned char CDEK_rk_C3[512];
   unsigned char CDEK_rk_C4[256];
   unsigned char Cert_owner_info[600];
   unsigned char Cert_owner_info_sign_value[256];
   unsigned char owner_grant_info[2144];
   unsigned char owner_grant_info_sign_value[256];
   unsigned char C_DEK_C1[256];
   unsigned char C_DEK_C2[256];
   unsigned char C_DEK_C3[512];
   unsigned char C_DEK_C4[256];

   int offset = 0;
   int reqestBodyOffset = 0;
   //ownerUseridLength(4 bytes) + ownerUserid(20 bytes)
   memset(ownerUserIdLengthStr, 0x00, sizeof(ownerUserIdLengthStr));
   memcpy(ownerUserIdLengthStr, requestBody + reqestBodyOffset, 4);
   reqestBodyOffset += 4;
   ownerUserIdLength = atoi(ownerUserIdLengthStr);
   if(ownerUserIdLength <= 0 || ownerUserIdLength > sizeof(ownerUserId))
    {
        printf("error ownerUserid length, ownerUserIdLength is %d \n", ownerUserIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(ownerUserId, requestBody + reqestBodyOffset, ownerUserIdLength);
    reqestBodyOffset += ownerUserIdLength;

    //sharedWithUserIdLength(4 bytes) + shareWithUserId(20 bytes) 
   memset(sharedWithUserIdLengthStr, 0x00, sizeof(sharedWithUserIdLengthStr));
   memcpy(sharedWithUserIdLengthStr, requestBody + reqestBodyOffset, 4);
   reqestBodyOffset += 4;
   sharedWithUserIdLength = atoi(sharedWithUserIdLengthStr);
   if(sharedWithUserIdLength <= 0 || sharedWithUserIdLength > sizeof(sharedWithUserId))
    {
        printf("error shareWithUserId length, sharedWithUserIdLength is %d \n", sharedWithUserIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(sharedWithUserId, requestBody + reqestBodyOffset, sharedWithUserIdLength);
    reqestBodyOffset += sharedWithUserIdLength;

    //shareIdLength(4 bytes) + shareId(50 bytes)
    memset(shareIdLengthStr, 0x00, sizeof(shareIdLengthStr));
    memcpy(shareIdLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    shareIdLength = atoi(shareIdLengthStr);
    if(shareIdLength <= 0 || shareIdLength > sizeof(filename))
    {
        printf("error shareId length, shareIdLength is %d \n", shareIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(shareId, requestBody + reqestBodyOffset, shareIdLength);
    reqestBodyOffset += shareIdLength;
    
    //fileIdLength(4 bytes) + fileId(50 bytes)
    memset(fileIdLengthStr, 0x00, sizeof(fileIdLengthStr));
    memcpy(fileIdLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    fileIdLength = atoi(fileIdLengthStr);
    if(fileIdLength <= 0 || fileIdLength > sizeof(filename))
    {
        printf("error fileId length, fileIdLength is %d \n", fileIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(fileId, requestBody + reqestBodyOffset, fileIdLength);
    reqestBodyOffset += fileIdLength;

    //filenameLength(4 bytes) + filename(256 bytes)
    memset(filenameLengthStr, 0x00, sizeof(filenameLengthStr));
    memcpy(filenameLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    filenameLength = atoi(filenameLengthStr);
    if(filenameLength <= 0 || filenameLength > sizeof(filename))
    {
        printf("error filename length, filenameLength is %d \n", filenameLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(filename, requestBody + reqestBodyOffset, filenameLength);
    reqestBodyOffset += filenameLength;

    //C_rk_length(4 bytes) + C_rk(568 bytes) 
    memset(C_rk_lengthStr, 0x00, sizeof(C_rk_lengthStr));
    memcpy(C_rk_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    C_rk_length = atoi(C_rk_lengthStr);
    if(C_rk_length <= 0 || C_rk_length > sizeof(C_rk))
    {
        printf("error C_rk length, C_rk_length is %d \n", C_rk_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(C_rk, requestBody + reqestBodyOffset, C_rk_length);
    reqestBodyOffset += C_rk_length;

    //CDEK_rk_C1_length(4 bytes) +  CDEK_rk_C1(256 bytes)
    memset(CDEK_rk_C1_lengthStr, 0x00, sizeof(CDEK_rk_C1_lengthStr));
    memcpy(CDEK_rk_C1_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    CDEK_rk_C1_length = atoi(CDEK_rk_C1_lengthStr);
    if(CDEK_rk_C1_length <= 0 || CDEK_rk_C1_length > sizeof(CDEK_rk_C1))
    {
        printf("error CDEK_rk_C1 length, CDEK_rk_C1_length is %d \n", CDEK_rk_C1_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(CDEK_rk_C1, requestBody + reqestBodyOffset, CDEK_rk_C1_length);
    reqestBodyOffset += CDEK_rk_C1_length;

    //CDEK_rk_C2_length(4 bytes) +  CDEK_rk_C2(256 bytes)
    memset(CDEK_rk_C2_lengthStr, 0x00, sizeof(CDEK_rk_C2_lengthStr));
    memcpy(CDEK_rk_C2_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    CDEK_rk_C2_length = atoi(CDEK_rk_C2_lengthStr);
    if(CDEK_rk_C2_length <= 0 || CDEK_rk_C2_length > sizeof(CDEK_rk_C2))
    {
        printf("error CDEK_rk_C2 length, CDEK_rk_C2_length is %d \n", CDEK_rk_C2_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(CDEK_rk_C2, requestBody + reqestBodyOffset, CDEK_rk_C2_length);
    reqestBodyOffset += CDEK_rk_C2_length;

    //CDEK_rk_C3_length(4 bytes) +  CDEK_rk_C3(512 bytes)
    memset(CDEK_rk_C3_lengthStr, 0x00, sizeof(CDEK_rk_C3_lengthStr));
    memcpy(CDEK_rk_C3_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    CDEK_rk_C3_length = atoi(CDEK_rk_C3_lengthStr);
    if(CDEK_rk_C3_length <= 0 || CDEK_rk_C3_length > sizeof(CDEK_rk_C3))
    {
        printf("error CDEK_rk_C3 length, CDEK_rk_C3_length is %d \n", CDEK_rk_C3_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(CDEK_rk_C3, requestBody + reqestBodyOffset, CDEK_rk_C3_length);
    reqestBodyOffset += CDEK_rk_C3_length;

    //CDEK_rk_C4_length(4 bytes) +  CDEK_rk_C4(256 bytes)
    memset(CDEK_rk_C4_lengthStr, 0x00, sizeof(CDEK_rk_C4_lengthStr));
    memcpy(CDEK_rk_C4_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    CDEK_rk_C4_length = atoi(CDEK_rk_C4_lengthStr);
    if(CDEK_rk_C4_length <= 0 || CDEK_rk_C4_length > sizeof(CDEK_rk_C4))
    {
        printf("error CDEK_rk_C4 length, CDEK_rk_C4_length is %d \n", CDEK_rk_C4_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(CDEK_rk_C4, requestBody + reqestBodyOffset, CDEK_rk_C4_length);
    reqestBodyOffset += CDEK_rk_C4_length;

    //Cert_owner_infoLength(4 bytes) + Cert_owner_info(600 bytes)
    memset(Cert_owner_infoLengthStr, 0x00, sizeof(Cert_owner_infoLengthStr));
    memcpy(Cert_owner_infoLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    Cert_owner_infoLength = atoi(Cert_owner_infoLengthStr);
    if(Cert_owner_infoLength <= 0 || Cert_owner_infoLength > sizeof(Cert_owner_info))
    {
        printf("error Cert_owner_info length, Cert_owner_infoLength is %d \n", Cert_owner_infoLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(Cert_owner_info, requestBody + reqestBodyOffset, Cert_owner_infoLength);
    reqestBodyOffset += Cert_owner_infoLength;

    //Cert_owner_info_sign_valueLength(4 bytes) + Cert_owner_info_sign_value(256 bytes)
    memset(Cert_owner_info_sign_valueLengthStr, 0x00, sizeof(Cert_owner_info_sign_valueLengthStr));
    memcpy(Cert_owner_info_sign_valueLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    Cert_owner_info_sign_valueLength = atoi(Cert_owner_info_sign_valueLengthStr);
    if(Cert_owner_info_sign_valueLength <= 0 || 
        Cert_owner_info_sign_valueLength > sizeof(Cert_owner_info_sign_value))
    {
        printf("error Cert_owner_info_sign_value length, Cert_owner_info_sign_valueLength is %d \n", Cert_owner_info_sign_valueLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(Cert_owner_info_sign_value, requestBody + reqestBodyOffset, Cert_owner_info_sign_valueLength);
    reqestBodyOffset += Cert_owner_info_sign_valueLength;

    //owner_grant_infoLength(4 bytes) + owner_grant_info(2144 bytes)
    memset(owner_grant_infoLengthStr, 0x00, sizeof(owner_grant_infoLengthStr));
    memcpy(owner_grant_infoLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    owner_grant_infoLength = atoi(owner_grant_infoLengthStr);
    if(owner_grant_infoLength <= 0 || 
        owner_grant_infoLength > sizeof(owner_grant_info))
    {
        printf("error owner_grant_info length, owner_grant_infoLength is %d \n", owner_grant_infoLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(owner_grant_info, requestBody + reqestBodyOffset, owner_grant_infoLength);
    reqestBodyOffset += owner_grant_infoLength;

    //owner_grant_info_sign_valueLength(4 bytes) + owner_grant_info_sign_value(256 bytes)
    memset(owner_grant_info_sign_valueLengthStr, 0x00, sizeof(owner_grant_info_sign_valueLengthStr));
    memcpy(owner_grant_info_sign_valueLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    owner_grant_info_sign_valueLength = atoi(owner_grant_info_sign_valueLengthStr);
    if(owner_grant_info_sign_valueLength <= 0 || 
        owner_grant_info_sign_valueLength > sizeof(owner_grant_info_sign_value))
    {
        printf("error owner_grant_info_sign_value length, owner_grant_info_sign_valueLength is %d \n", owner_grant_info_sign_valueLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(owner_grant_info_sign_value, requestBody + reqestBodyOffset, owner_grant_info_sign_valueLength);
    reqestBodyOffset += owner_grant_info_sign_valueLength;

    //C_DEK_C1_length(4 bytes) +  C_DEK_C1(256 bytes)
    memset(C_DEK_C1_lengthStr, 0x00, sizeof(C_DEK_C1_lengthStr));
    memcpy(C_DEK_C1_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    C_DEK_C1_length = atoi(C_DEK_C1_lengthStr);
    if(C_DEK_C1_length <= 0 || 
        C_DEK_C1_length > sizeof(C_DEK_C1))
    {
        printf("error C_DEK_C1 length, C_DEK_C1_length is %d \n", C_DEK_C1_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(C_DEK_C1, requestBody + reqestBodyOffset, C_DEK_C1_length);
    reqestBodyOffset += C_DEK_C1_length;

    //C_DEK_C2_length(4 bytes) +  C_DEK_C2(256 bytes)
    memset(C_DEK_C2_lengthStr, 0x00, sizeof(C_DEK_C2_lengthStr));
    memcpy(C_DEK_C2_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    C_DEK_C2_length = atoi(C_DEK_C2_lengthStr);
    if(C_DEK_C2_length <= 0 || 
        C_DEK_C2_length > sizeof(C_DEK_C2))
    {
        printf("error C_DEK_C2 length, C_DEK_C2_length is %d \n", C_DEK_C2_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(C_DEK_C2, requestBody + reqestBodyOffset, C_DEK_C2_length);
    reqestBodyOffset += C_DEK_C2_length;

    //C_DEK_C3_length(4 bytes) +  C_DEK_C3(512 bytes)
    memset(C_DEK_C3_lengthStr, 0x00, sizeof(C_DEK_C3_lengthStr));
    memcpy(C_DEK_C3_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    C_DEK_C3_length = atoi(C_DEK_C3_lengthStr);
    if(C_DEK_C3_length <= 0 || 
        C_DEK_C3_length > sizeof(C_DEK_C3))
    {
        printf("error C_DEK_C3 length, C_DEK_C3_length is %d \n", C_DEK_C3_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(C_DEK_C3, requestBody + reqestBodyOffset, C_DEK_C3_length);
    reqestBodyOffset += C_DEK_C3_length;

    //C_DEK_C4_length(4 bytes) +  C_DEK_C4(256 bytes)
    memset(C_DEK_C4_lengthStr, 0x00, sizeof(C_DEK_C4_lengthStr));
    memcpy(C_DEK_C4_lengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    C_DEK_C4_length = atoi(C_DEK_C4_lengthStr);
    if(C_DEK_C4_length <= 0 || 
        C_DEK_C4_length > sizeof(C_DEK_C4))
    {
        printf("error C_DEK_C4 length, C_DEK_C4_length is %d \n", C_DEK_C4_length);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(C_DEK_C4, requestBody + reqestBodyOffset, C_DEK_C4_length);
    reqestBodyOffset += C_DEK_C4_length;
#ifdef PRINT_DEBUG_INFO
    printf("ownerUserIdLength is %d, ownerUserId is :\n", ownerUserIdLength);
    dump_hex(ownerUserId, ownerUserIdLength, 16);

    printf("sharedWithUserIdLength is %d, sharedWithUserId is :\n", sharedWithUserIdLength);
    dump_hex(sharedWithUserId, sharedWithUserIdLength, 16);
    
    printf("shareIdLength is %d, fileId is :\n", shareIdLength);
    dump_hex(shareId, shareIdLength, 16);

    printf("fileIdLength is %d, fileId is :\n", fileIdLength);
    dump_hex(fileId, fileIdLength, 16);

    printf("filenameLength is %d, filename is :\n", filenameLength);
    dump_hex(filename, filenameLength, 16);

    printf("C_rk_length is %d, C_rk is :\n", C_rk_length);
    dump_hex(C_rk, C_rk_length, 16);

    printf("CDEK_rk_C1_length is %d, CDEK_rk_C1 is :\n", CDEK_rk_C1_length);
    dump_hex(CDEK_rk_C1, CDEK_rk_C1_length, 16);

    printf("CDEK_rk_C2_length is %d, CDEK_rk_C2 is :\n", CDEK_rk_C2_length);
    dump_hex(CDEK_rk_C2, CDEK_rk_C2_length, 16);

    printf("CDEK_rk_C3_length is %d, CDEK_rk_C3 is :\n", CDEK_rk_C3_length);
    dump_hex(CDEK_rk_C3, CDEK_rk_C3_length, 16);

    printf("CDEK_rk_C4_length is %d, CDEK_rk_C4 is :\n", CDEK_rk_C4_length);
    dump_hex(CDEK_rk_C4, CDEK_rk_C4_length, 16);

    printf("Cert_owner_infoLength is %d, Cert_owner_info is :\n", Cert_owner_infoLength);
    dump_hex(Cert_owner_info, Cert_owner_infoLength, 16);

    printf("Cert_owner_info_sign_valueLength is %d, Cert_owner_info_sign_value is :\n", Cert_owner_info_sign_valueLength);
    dump_hex(Cert_owner_info_sign_value, Cert_owner_info_sign_valueLength, 16);

    printf("owner_grant_infoLength is %d, owner_grant_info is :\n", owner_grant_infoLength);
    dump_hex(owner_grant_info, owner_grant_infoLength, 16);

    printf("owner_grant_info_sign_valueLength is %d, owner_grant_info_sign_value is :\n", owner_grant_info_sign_valueLength);
    dump_hex(owner_grant_info_sign_value, owner_grant_info_sign_valueLength, 16);

    printf("C_DEK_C1_length is %d, C_DEK_C1 is :\n", C_DEK_C1_length);
    dump_hex(C_DEK_C1, C_DEK_C1_length, 16);

    printf("C_DEK_C2_length is %d, C_DEK_C2 is :\n", C_DEK_C2_length);
    dump_hex(C_DEK_C2, C_DEK_C2_length, 16);

    printf("C_DEK_C3_length is %d, C_DEK_C3 is :\n", C_DEK_C3_length);
    dump_hex(C_DEK_C3, C_DEK_C3_length, 16);

    printf("C_DEK_C4_length is %d, C_DEK_C4 is :\n", C_DEK_C4_length);
    dump_hex(C_DEK_C4, C_DEK_C4_length, 16);
#endif
    sgx_status_t retval;
#ifdef TIME_COST
    struct timespec start, end;
    long long elapsedTime;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    sgx_status_t ret = t_SaveShareFile(global_eid, &retval, 
        ownerUserId, ownerUserIdLength,
        sharedWithUserId, sharedWithUserIdLength,
        shareId, shareIdLength,
        fileId, fileIdLength,
        filename, filenameLength, 
        C_rk, C_rk_length, 
        CDEK_rk_C1, CDEK_rk_C1_length, 
        CDEK_rk_C2, CDEK_rk_C2_length, 
        CDEK_rk_C3, CDEK_rk_C3_length, 
        CDEK_rk_C4, CDEK_rk_C4_length, 
        Cert_owner_info, Cert_owner_infoLength, 
        Cert_owner_info_sign_value, Cert_owner_info_sign_valueLength,
        owner_grant_info, owner_grant_infoLength,
        owner_grant_info_sign_value, owner_grant_info_sign_valueLength,
        C_DEK_C1, C_DEK_C1_length,
        C_DEK_C2, C_DEK_C2_length,
        C_DEK_C3, C_DEK_C3_length,
        C_DEK_C4, C_DEK_C4_length);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsedTime = (end.tv_sec - start.tv_sec) * 1000000000l + (end.tv_nsec - start.tv_nsec);
    printf("t_SaveShareFile Elapsed time: %ld nanoseconds\n", elapsedTime);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_SaveShareFile failed.\n");
        print_error_message(ret);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }
    printf("Call t_SaveShareFile success.\n");

    /*
    seal shareFile data
    */
   // Get the sealed data size
    uint32_t sealed_data_size = 0;
#ifdef TIME_COST
    struct timespec start_getSealSize, end_getSealSize;
    long long elapsedTime_getSealSize;
    clock_gettime(CLOCK_MONOTONIC, &start_getSealSize);
#endif
    ret = t_get_sealed_shareFileList_data_size(global_eid, &sealed_data_size);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end_getSealSize);
    elapsedTime_getSealSize = (end_getSealSize.tv_sec - start_getSealSize.tv_sec) * 1000000000l + 
        (end_getSealSize.tv_nsec - start_getSealSize.tv_nsec);
    printf("t_get_sealed_shareFileList_data_size Elapsed time: %ld nanoseconds\n", elapsedTime_getSealSize);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_get_sealed_shareFileList_data_size failed.\n");
        print_error_message(ret);
        packResp((unsigned char *)"0103", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -3;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        // sgx_destroy_enclave(global_eid);
        printf("sealed_data_size equal to %ld.\n", UINT32_MAX);
        packResp((unsigned char *)"0103", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -3;
    }
    printf("Call t_get_sealed_shareFileList_data_size success.\n");
    if(sealed_data_size == 0) {
        printf("no share file need to seal, delete %s\n", SEALED_shareFileList_DATA_FILE);
        remove_file(SEALED_shareFileList_DATA_FILE);
    } 
    else {
        uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
        if (temp_sealed_buf == NULL)
        {
            printf("Out of memory\n");
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_MEMORY_ERROR, strlen(ERRORMSG_MEMORY_ERROR),
                responseMsg, p_responseMsgLength);
            return -2;
        }
#ifdef TIME_COST
        struct timespec start_Seal, end_Seal;
        long long elapsedTime_Seal;
        clock_gettime(CLOCK_MONOTONIC, &start_Seal);
#endif
        ret = t_seal_shareFileList_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
#ifdef TIME_COST
        clock_gettime(CLOCK_MONOTONIC, &end_Seal);
        elapsedTime_Seal = (end_Seal.tv_sec - start_Seal.tv_sec) * 1000000000l + 
            (end_Seal.tv_nsec - start_Seal.tv_nsec);
        printf("t_seal_shareFileList_data Elapsed time: %ld nanoseconds\n", elapsedTime_Seal);
#endif
        if (ret != SGX_SUCCESS)
        {
            printf("call t_seal_shareFileList_data failed\n");
            print_error_message(ret);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
                responseMsg, p_responseMsgLength);
            return -3;
        }
        else if (retval != SGX_SUCCESS)
        {
            printf("call t_seal_shareFileList_data failed, retval=%d\n", retval);
            print_error_message(retval);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
                responseMsg, p_responseMsgLength);
            return -3;
        }
        printf("Call t_seal_shareFileList_data success.\n");

        if (write_buf_to_file(SEALED_shareFileList_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
        {
            printf("Failed to save the sealed data blob to \" %s \" \n", SEALED_shareFileList_DATA_FILE);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0104", 4, 
                (unsigned char *)ERRORMSG_FILE_IO_ERROR, strlen(ERRORMSG_FILE_IO_ERROR),
                responseMsg, p_responseMsgLength);
            return -2;
        }
        printf("Call write_buf_to_file success.\n");

        free(temp_sealed_buf);
        printf("seal data success.\n");
    }
    // set successful respond
    memcpy(responseMsg, "00000000", 8);
    (*p_responseMsgLength) = 8;
    printf("handleRequest0003 succeeded.\n");
    return 0;
}

int handleRequest0004(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    
    /*
    userIdLength(4 bytes) + userId(20 bytes) + 
    shareIdLength(4 bytes) + shareId(50 bytes) +
    fileIdLength(4 bytes) + fileId(50 bytes) + 
    filenameLength(4 bytes) + filename(256 bytes) +
    Cert_user_infoLength(4 bytes) + Cert_user_info(600 bytes) +  
    Cert_user_info_sign_valueLength(4 bytes) + Cert_user_info_sign_value(256 bytes) 

    */
   
   size_t userIdLength, shareIdLength, fileIdLength, filenameLength;
   size_t Cert_user_infoLength, Cert_user_info_sign_valueLength;

   char userIdLengthStr[5];
   char shareIdLengthStr[5];
   char fileIdLengthStr[5];
   char filenameLengthStr[5];
   char Cert_user_infoLengthStr[5];
   char Cert_user_info_sign_valueLengthStr[5];

   unsigned char userId[20];
   unsigned char shareId[50];
   unsigned char fileId[50];
   unsigned char filename[256];
   unsigned char Cert_user_info[600];
   unsigned char Cert_user_info_sign_value[256];

   int offset = 0;
   int reqestBodyOffset = 0;
   //userIdLength(4 bytes) + userId(20 bytes) 
   memset(userIdLengthStr, 0x00, sizeof(userIdLengthStr));
   memcpy(userIdLengthStr, requestBody + reqestBodyOffset, 4);
   reqestBodyOffset += 4;
   userIdLength = atoi(userIdLengthStr);
   if(userIdLength <= 0 || userIdLength > sizeof(userId))
    {
        printf("error userId length, userId is %d \n", userIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(userId, requestBody + reqestBodyOffset, userIdLength);
    reqestBodyOffset += userIdLength;

    //shareIdLength(4 bytes) + shareId(50 bytes)
    memset(shareIdLengthStr, 0x00, sizeof(shareIdLengthStr));
    memcpy(shareIdLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    shareIdLength = atoi(shareIdLengthStr);
    if(shareIdLength <= 0 || shareIdLength > sizeof(shareId))
    {
        printf("error shareId length, shareIdLength is %d \n", shareIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(shareId, requestBody + reqestBodyOffset, shareIdLength);
    reqestBodyOffset += shareIdLength;
    
    //fileIdLength(4 bytes) + fileId(50 bytes)
    memset(fileIdLengthStr, 0x00, sizeof(fileIdLengthStr));
    memcpy(fileIdLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    fileIdLength = atoi(fileIdLengthStr);
    if(fileIdLength <= 0 || fileIdLength > sizeof(fileId))
    {
        printf("error fileId length, fileIdLength is %d \n", fileIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(fileId, requestBody + reqestBodyOffset, fileIdLength);
    reqestBodyOffset += fileIdLength;

    //filenameLength(4 bytes) + filename(256 bytes)
    memset(filenameLengthStr, 0x00, sizeof(filenameLengthStr));
    memcpy(filenameLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    filenameLength = atoi(filenameLengthStr);
    if(filenameLength <= 0 || filenameLength > sizeof(filename))
    {
        printf("error filename length, filenameLength is %d \n", filenameLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(filename, requestBody + reqestBodyOffset, filenameLength);
    reqestBodyOffset += filenameLength;

    //Cert_user_infoLength(4 bytes) + Cert_user_info(600 bytes) 
    memset(Cert_user_infoLengthStr, 0x00, sizeof(Cert_user_infoLengthStr));
    memcpy(Cert_user_infoLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    Cert_user_infoLength = atoi(Cert_user_infoLengthStr);
    if(Cert_user_infoLength <= 0 || Cert_user_infoLength > sizeof(Cert_user_info))
    {
        printf("error Cert_user_info length, Cert_user_infoLength is %d \n", Cert_user_infoLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(Cert_user_info, requestBody + reqestBodyOffset, Cert_user_infoLength);
    reqestBodyOffset += Cert_user_infoLength;

    //Cert_user_info_sign_valueLength(4 bytes) + Cert_user_info_sign_value(256 bytes) 
    memset(Cert_user_info_sign_valueLengthStr, 0x00, sizeof(Cert_user_info_sign_valueLengthStr));
    memcpy(Cert_user_info_sign_valueLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    Cert_user_info_sign_valueLength = atoi(Cert_user_info_sign_valueLengthStr);
    if(Cert_user_info_sign_valueLength <= 0 || Cert_user_info_sign_valueLength > sizeof(Cert_user_info_sign_value))
    {
        printf("error Cert_user_info_sign_value length, Cert_user_info_sign_valueLength is %d \n", Cert_user_info_sign_valueLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(Cert_user_info_sign_value, requestBody + reqestBodyOffset, Cert_user_info_sign_valueLength);
    reqestBodyOffset += Cert_user_info_sign_valueLength;
#ifdef PRINT_DEBUG_INFO
    printf("userIdLength is %d, userId is :\n", userIdLength);
    dump_hex(userId, userIdLength, 16);
    
    printf("shareIdLength is %d, fileId is :\n", shareIdLength);
    dump_hex(shareId, shareIdLength, 16);

    printf("fileIdLength is %d, fileId is :\n", fileIdLength);
    dump_hex(fileId, fileIdLength, 16);

    printf("filenameLength is %d, filename is :\n", filenameLength);
    dump_hex(filename, filenameLength, 16);

    printf("Cert_user_infoLength is %d, Cert_user_info is :\n", Cert_user_infoLength);
    dump_hex(Cert_user_info, Cert_user_infoLength, 16);

    printf("Cert_user_info_sign_valueLength is %d, Cert_user_info_sign_value is :\n", Cert_user_info_sign_valueLength);
    dump_hex(Cert_user_info_sign_value, Cert_user_info_sign_valueLength, 16);
#endif
    uint8_t TC_DEK_c1_Hex[256 + 1];
    uint8_t TC_DEK_c2_Hex[256 + 1];
    uint8_t TC_DEK_c3_Hex[512 + 1];
    uint8_t TC_DEK_c4_Hex[256 + 1];
    memset(TC_DEK_c1_Hex, 0x00, sizeof(TC_DEK_c1_Hex));
    memset(TC_DEK_c2_Hex, 0x00, sizeof(TC_DEK_c2_Hex));
    memset(TC_DEK_c3_Hex, 0x00, sizeof(TC_DEK_c3_Hex));
    memset(TC_DEK_c4_Hex, 0x00, sizeof(TC_DEK_c4_Hex));
    sgx_status_t retval;
#ifdef TIME_COST
    struct timespec start, end;
    long long elapsedTime;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    sgx_status_t ret = t_ReEnc(global_eid, &retval, 
        userId, userIdLength, 
        shareId, shareIdLength, 
        fileId, fileIdLength, 
        filename, filenameLength, 
        Cert_user_info, Cert_user_infoLength, 
        Cert_user_info_sign_value, Cert_user_info_sign_valueLength,
        TC_DEK_c1_Hex, sizeof(TC_DEK_c1_Hex), 
        TC_DEK_c2_Hex, sizeof(TC_DEK_c2_Hex), 
        TC_DEK_c3_Hex, sizeof(TC_DEK_c3_Hex), 
        TC_DEK_c4_Hex, sizeof(TC_DEK_c4_Hex));
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsedTime = (end.tv_sec - start.tv_sec) * 1000000000l + (end.tv_nsec - start.tv_nsec);
    printf("t_ReEnc Elapsed time: %ld nanoseconds\n", elapsedTime);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_ReEnc failed.\n");
        print_error_message(ret);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }
    printf("Call t_ReEnc success.\n");

    /*
    seal shareFile data(due to a record was deleted in t_ReEnc)
    */
   // Get the sealed data size
    uint32_t sealed_data_size = 0;
#ifdef TIME_COST
    struct timespec start_getSealSize, end_getSealSize;
    long long elapsedTime_getSealSize;
    clock_gettime(CLOCK_MONOTONIC, &start_getSealSize);
#endif
    ret = t_get_sealed_shareFileList_data_size(global_eid, &sealed_data_size);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end_getSealSize);
    elapsedTime_getSealSize = (end_getSealSize.tv_sec - start_getSealSize.tv_sec) * 1000000000l + 
        (end_getSealSize.tv_nsec - start_getSealSize.tv_nsec);
    printf("t_get_sealed_shareFileList_data_size Elapsed time: %ld nanoseconds\n", elapsedTime_getSealSize);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_get_sealed_shareFileList_data_size failed.\n");
        print_error_message(ret);
        packResp((unsigned char *)"0103", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -3;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        // sgx_destroy_enclave(global_eid);
        printf("sealed_data_size equal to %ld.\n", UINT32_MAX);
        packResp((unsigned char *)"0103", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -3;
    }
    printf("Call t_get_sealed_shareFileList_data_size success.\n");
    if(sealed_data_size == 0) {
        printf("no share file need to seal, delete %s\n", SEALED_shareFileList_DATA_FILE);
        remove_file(SEALED_shareFileList_DATA_FILE);
    } 
    else {
        uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
        if (temp_sealed_buf == NULL)
        {
            printf("Out of memory\n");
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_MEMORY_ERROR, strlen(ERRORMSG_MEMORY_ERROR),
                responseMsg, p_responseMsgLength);
            return -2;
        }
#ifdef TIME_COST
        struct timespec start_Seal, end_Seal;
        long long elapsedTime_Seal;
        clock_gettime(CLOCK_MONOTONIC, &start_Seal);
#endif
        ret = t_seal_shareFileList_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
#ifdef TIME_COST
        clock_gettime(CLOCK_MONOTONIC, &end_Seal);
        elapsedTime_Seal = (end_Seal.tv_sec - start_Seal.tv_sec) * 1000000000l + 
            (end_Seal.tv_nsec - start_Seal.tv_nsec);
        printf("t_seal_shareFileList_data Elapsed time: %ld nanoseconds\n", elapsedTime_Seal);
#endif
        if (ret != SGX_SUCCESS)
        {
            printf("call t_seal_shareFileList_data failed\n");
            print_error_message(ret);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
                responseMsg, p_responseMsgLength);
            return -3;
        }
        else if (retval != SGX_SUCCESS)
        {
            printf("call t_seal_shareFileList_data failed, retval=%d\n", retval);
            print_error_message(retval);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
                responseMsg, p_responseMsgLength);
            return -3;
        }
        printf("Call t_seal_shareFileList_data success.\n");

        if (write_buf_to_file(SEALED_shareFileList_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
        {
            printf("Failed to save the sealed data blob to \" %s \" \n", SEALED_shareFileList_DATA_FILE);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0104", 4, 
                (unsigned char *)ERRORMSG_FILE_IO_ERROR, strlen(ERRORMSG_FILE_IO_ERROR),
                responseMsg, p_responseMsgLength);
            return -2;
        }
        printf("Call write_buf_to_file success.\n");

        printf("Sealing data succeeded.\n");

        free(temp_sealed_buf);
    }
    // set successful respond
    // add return msg
    size_t responseBodyLen = 4 + 50 + 4 + 256 + 4 + 256 + 4 + 512 + 4 + 256;
    uint8_t responseBody[responseBodyLen];
    memset(responseBody, 0x00, sizeof(responseBody));
    offset = 0;
    sprintf((char *)(responseBody + offset), "%04d", shareIdLength);
    offset += 4;
    memcpy(responseBody + offset, shareId, shareIdLength);
    offset += shareIdLength;

    sprintf((char *)(responseBody + offset), "%04d", 256);
    offset += 4;
    memcpy(responseBody + offset, TC_DEK_c1_Hex, 256);
    offset += 256;

    sprintf((char *)(responseBody + offset), "%04d", 256);
    offset += 4;
    memcpy(responseBody + offset, TC_DEK_c2_Hex, 256);
    offset += 256;

    sprintf((char *)(responseBody + offset), "%04d", 512);
    offset += 4;
    memcpy(responseBody + offset, TC_DEK_c3_Hex, 512);
    offset += 512;

    sprintf((char *)(responseBody + offset), "%04d", 256);
    offset += 4;
    memcpy(responseBody + offset, TC_DEK_c4_Hex, 256);
    offset += 256;

    packResp((unsigned char *)"0000", 4, 
            (unsigned char *)responseBody, offset,
            responseMsg, p_responseMsgLength);

    printf("handleRequest0004 succeeded.\n");
    return 0;
}

int handleRequest0005(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    
    /*
    userIdLength(4 bytes) + userId(20 bytes) + 
    revokeUserIdLength(4 bytes) + revokeUserId(20 bytes) + 
    revoke_sign_valueLength(4 bytes) + revoke_sign_value(256 bytes)
    */
   
   size_t userIdLength, revokeUserIdLength, revoke_sign_valueLength;

   char userIdLengthStr[5];
   char revokeUserIdLengthStr[5];
   char revoke_sign_valueLengthStr[5];

   unsigned char userId[20];
   unsigned char revokeUserId[20];
   unsigned char revoke_sign_value[256];

   int offset = 0;
   int reqestBodyOffset = 0;
   //userIdLength(4 bytes) + userId(20 bytes) 
   memset(userIdLengthStr, 0x00, sizeof(userIdLengthStr));
   memcpy(userIdLengthStr, requestBody + reqestBodyOffset, 4);
   reqestBodyOffset += 4;
   userIdLength = atoi(userIdLengthStr);
   if(userIdLength <= 0 || userIdLength > sizeof(userId))
    {
        printf("error userId length, userId is %d \n", userIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(userId, requestBody + reqestBodyOffset, userIdLength);
    reqestBodyOffset += userIdLength;

    //revokeUserIdLength(4 bytes) + revokeUserId(20 bytes)
    memset(revokeUserIdLengthStr, 0x00, sizeof(revokeUserIdLengthStr));
    memcpy(revokeUserIdLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    revokeUserIdLength = atoi(revokeUserIdLengthStr);
    if(revokeUserIdLength <= 0 || revokeUserIdLength > sizeof(revokeUserId))
    {
        printf("error revokeUserId length, revokeUserIdLength is %d \n", revokeUserIdLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(revokeUserId, requestBody + reqestBodyOffset, revokeUserIdLength);
    reqestBodyOffset += revokeUserIdLength;
    
    //revoke_sign_valueLength(4 bytes) + revoke_sign_value(256 bytes)
    memset(revoke_sign_valueLengthStr, 0x00, sizeof(revoke_sign_valueLengthStr));
    memcpy(revoke_sign_valueLengthStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    revoke_sign_valueLength = atoi(revoke_sign_valueLengthStr);
    if(revoke_sign_valueLength <= 0 || revoke_sign_valueLength > sizeof(revoke_sign_value))
    {
        printf("error revoke_sign_value length, revoke_sign_valueLength is %d \n", revoke_sign_valueLength);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(revoke_sign_value, requestBody + reqestBodyOffset, revoke_sign_valueLength);
    reqestBodyOffset += revoke_sign_valueLength;
#ifdef PRINT_DEBUG_INFO
    printf("userIdLength is %d, userId is :\n", userIdLength);
    dump_hex(userId, userIdLength, 16);
    
    printf("revokeUserIdLength is %d, revokeUserId is :\n", revokeUserIdLength);
    dump_hex(revokeUserId, revokeUserIdLength, 16);

    printf("revoke_sign_valueLength is %d, revoke_sign_value is :\n", revoke_sign_valueLength);
    dump_hex(revoke_sign_value, revoke_sign_valueLength, 16);
#endif
    sgx_status_t retval;
#ifdef TIME_COST
    struct timespec start, end;
    long long elapsedTime;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    sgx_status_t ret = t_revoke(global_eid, &retval, 
        revokeUserId, revokeUserIdLength, 
        revoke_sign_value, revoke_sign_valueLength);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsedTime = (end.tv_sec - start.tv_sec) * 1000000000l + (end.tv_nsec - start.tv_nsec);
    printf("t_revoke Elapsed time: %ld nanoseconds\n", elapsedTime);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_revoke failed.\n");
        print_error_message(ret);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }
    printf("Call t_revoke success.\n");

    /*
    seal UserRevocationList data
    */
   // Get the sealed data size
    uint32_t sealed_data_size = 0;
#ifdef TIME_COST
    struct timespec start_getSealSize, end_getSealSize;
    long long elapsedTime_getSealSize;
    clock_gettime(CLOCK_MONOTONIC, &start_getSealSize);
#endif
    ret = t_get_sealed_UserRevocationList_data_size(global_eid, &sealed_data_size);
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end_getSealSize);
    elapsedTime_getSealSize = (end_getSealSize.tv_sec - start_getSealSize.tv_sec) * 1000000000l + 
        (end_getSealSize.tv_nsec - start_getSealSize.tv_nsec);
    printf("t_get_sealed_UserRevocationList_data_size Elapsed time: %ld nanoseconds\n", elapsedTime_getSealSize);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_get_sealed_UserRevocationList_data_size failed.\n");
        print_error_message(ret);
        packResp((unsigned char *)"0103", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -3;
    }
    else if (sealed_data_size == UINT32_MAX)
    {
        // sgx_destroy_enclave(global_eid);
        printf("sealed_data_size equal to %ld.\n", UINT32_MAX);
        packResp((unsigned char *)"0103", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -3;
    }
    printf("Call t_get_sealed_UserRevocationList_data_size success.\n");
    if(sealed_data_size == 0) {
        printf("no UserRevocationList need to seal, delete %s\n", SEALED_UserRevocationList_DATA_FILE);
        remove_file(SEALED_UserRevocationList_DATA_FILE);
    } 
    else {
        uint8_t *temp_sealed_buf = (uint8_t *)malloc(sealed_data_size);
        if (temp_sealed_buf == NULL)
        {
            printf("Out of memory\n");
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_MEMORY_ERROR, strlen(ERRORMSG_MEMORY_ERROR),
                responseMsg, p_responseMsgLength);
            return -2;
        }
#ifdef TIME_COST
        struct timespec start_Seal, end_Seal;
        long long elapsedTime_Seal;
        clock_gettime(CLOCK_MONOTONIC, &start_Seal);
#endif
        ret = t_seal_UserRevocationList_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
#ifdef TIME_COST
        clock_gettime(CLOCK_MONOTONIC, &end_Seal);
        elapsedTime_Seal = (end_Seal.tv_sec - start_Seal.tv_sec) * 1000000000l + 
            (end_Seal.tv_nsec - start_Seal.tv_nsec);
        printf("t_seal_UserRevocationList_data Elapsed time: %ld nanoseconds\n", elapsedTime_Seal);
#endif
        if (ret != SGX_SUCCESS)
        {
            printf("call t_seal_UserRevocationList_data failed\n");
            print_error_message(ret);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
                responseMsg, p_responseMsgLength);
            return -3;
        }
        else if (retval != SGX_SUCCESS)
        {
            printf("call t_seal_UserRevocationList_data failed, retval=%d\n", retval);
            print_error_message(retval);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0103", 4, 
                (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
                responseMsg, p_responseMsgLength);
            return -3;
        }
        printf("Call t_seal_UserRevocationList_data success.\n");

        if (write_buf_to_file(SEALED_UserRevocationList_DATA_FILE, temp_sealed_buf, sealed_data_size, 0) == false)
        {
            printf("Failed to save the sealed data blob to \" %s \" \n", SEALED_UserRevocationList_DATA_FILE);
            free(temp_sealed_buf);
            packResp((unsigned char *)"0104", 4, 
                (unsigned char *)ERRORMSG_FILE_IO_ERROR, strlen(ERRORMSG_FILE_IO_ERROR),
                responseMsg, p_responseMsgLength);
            return -2;
        }
        printf("Call write_buf_to_file success.\n");

        printf("Sealing data succeeded.\n");

        free(temp_sealed_buf);
    }
    // set successful respond
    memcpy(responseMsg, "00000000", 8);
    (*p_responseMsgLength) = 8;

    printf("handleRequest0005 succeeded.\n");
    return 0;
}

int handleRequest1001(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    
    /*
    wLen(4 bytes) + w(256 bytes) +
    c1Length(4 bytes) + c1 + 
    c2Length(4 bytes) + c2 + 
    c3Length(4 bytes) + c3 + 
    c4Length(4 bytes) + c4
    */
   
   size_t wLen, c1Len, c2Len, c3Len, c4Len;
   char wLenStr[5];
   char c1LenStr[5];
   char c2LenStr[5];
   char c3LenStr[5];
   char c4LenStr[5];

   unsigned char w[BUFSIZ];
   unsigned char c1[256];
   unsigned char c2[256];
   unsigned char c3[512];
   unsigned char c4[256];

   int offset = 0;
   int reqestBodyOffset = 0;
   //w
   memset(wLenStr, 0x00, sizeof(wLenStr));
   memcpy(wLenStr, requestBody + reqestBodyOffset, 4);
   reqestBodyOffset += 4;
   wLen = atoi(wLenStr);
   if(wLen <= 0 || wLen > sizeof(w))
    {
        printf("error w length, wLen is %d \n", wLen);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(w, requestBody + reqestBodyOffset, wLen);
    reqestBodyOffset += wLen;

    //c1
    memset(c1LenStr, 0x00, sizeof(c1LenStr));
    memcpy(c1LenStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    c1Len = atoi(c1LenStr);
    if(c1Len <= 0 || c1Len > sizeof(c1))
    {
        printf("error c1 length, c1Len is %d \n", c1Len);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(c1, requestBody + reqestBodyOffset, c1Len);
    reqestBodyOffset += c1Len;

    //c2
    memset(c2LenStr, 0x00, sizeof(c2LenStr));
    memcpy(c2LenStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    c2Len = atoi(c2LenStr);
    if(c2Len <= 0 || c2Len > sizeof(c2))
    {
        printf("error c2 length, c2Len is %d \n", c2Len);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(c2, requestBody + reqestBodyOffset, c2Len);
    reqestBodyOffset += c2Len;

    //c3
    memset(c3LenStr, 0x00, sizeof(c3LenStr));
    memcpy(c3LenStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    c3Len = atoi(c3LenStr);
    if(c3Len <= 0 || c3Len > sizeof(c3))
    {
        printf("error c3 length, c3Len is %d \n", c3Len);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(c3, requestBody + reqestBodyOffset, c3Len);
    reqestBodyOffset += c3Len;

    //c4
    memset(c4LenStr, 0x00, sizeof(c4LenStr));
    memcpy(c4LenStr, requestBody + reqestBodyOffset, 4);
    reqestBodyOffset += 4;
    c4Len = atoi(c4LenStr);
    if(c4Len <= 0 || c4Len > sizeof(c4))
    {
        printf("error c4 length, c4Len is %d \n", c4Len);
        packResp((unsigned char *)"0101", 4, 
            (unsigned char *)ERRORMSG_REQUEST_ERROR, strlen(ERRORMSG_REQUEST_ERROR),
            responseMsg, p_responseMsgLength);
        return -1;
    }
    memcpy(c4, requestBody + reqestBodyOffset, c4Len);
    reqestBodyOffset += c4Len;

#ifdef PRINT_DEBUG_INFO
    printf("wLen is %d, w is :\n", wLen);
    dump_hex(w, wLen, 16);
    printf("c1Len is %d, c1 is :\n", c1Len);
    dump_hex(c1, c1Len, 16);
    printf("c2Len is %d, c2 is :\n", c2Len);
    dump_hex(c2, c2Len, 16);
    printf("c3Len is %d, c3 is :\n", c3Len);
    dump_hex(c3, c3Len, 16);
    printf("c4Len is %d, c4 is :\n", c4Len);
    dump_hex(c4, c4Len, 16);
#endif
    unsigned char m_bytes[SHA256_DIGEST_LENGTH_32];

    sgx_status_t retval;
#ifdef TIME_COST
    struct timespec start, end;
    long long elapsedTime;
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif
    sgx_status_t ret = t_Dec2(global_eid, &retval, w, wLen, 
        c1, c1Len, c2, c2Len, 
        c3, c3Len, c4, c4Len,
        m_bytes, sizeof(m_bytes));
#ifdef TIME_COST
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsedTime = (end.tv_sec - start.tv_sec) * 1000000000l + (end.tv_nsec - start.tv_nsec);
    printf("t_Dec2 Elapsed time: %ld nanoseconds\n", elapsedTime);
#endif
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_Dec2 failed.\n");
        print_error_message(ret);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        packResp((unsigned char *)"0102", 4, 
            (unsigned char *)ERRORMSG_SGX_ERROR, strlen(ERRORMSG_SGX_ERROR),
            responseMsg, p_responseMsgLength);
        return -2;
    }

    // set successful respond
    unsigned char respBody[SHA256_DIGEST_LENGTH_32 + 4];
    sprintf((char *)respBody, "%04d", SHA256_DIGEST_LENGTH_32);
    memcpy(respBody + 4, m_bytes, sizeof(m_bytes));
    packResp((unsigned char *)"0000", 4, 
            respBody, sizeof(respBody),
            responseMsg, p_responseMsgLength);
    printf("handleRequest1001 succeeded.\n");
    return 0;
}

int handleRequest1002(unsigned char *requestBody, size_t requestBodyLength,
    unsigned char *responseMsg, size_t * p_responseMsgLength) {
    
    /*
    input:
    userid Length(4 bytes) + userid(<=20 bytes)
    */
   
   size_t userIdLength;
   char userIdLengthStr[5];
   unsigned char userId[20];
   int offset = 0;

   memset(userIdLengthStr, 0x00, sizeof(userIdLengthStr));
   memcpy(userIdLengthStr, requestBody, 4);
   userIdLength = atoi(userIdLengthStr);
   if(userIdLength <= 0 || userIdLength > sizeof(userId))
    {
        printf("error userId length, userId is %d \n", userIdLength);
        int len = strlen(ERRORMSG_REQUEST_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0101", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_REQUEST_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -1;
    }
    memcpy(userId, requestBody + 4, userIdLength);
#ifdef PRINT_DEBUG_INFO
    printf("userIdLength is %d, userId is :\n", userIdLength);
    dump_hex(userId, userIdLength, 16);
#endif
    sgx_status_t retval;
    unsigned char ek_TEE[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    sgx_status_t ret = t_RetrieveEkTee(global_eid, &retval, ek_TEE, sizeof(ek_TEE));
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_RetrieveEkTee failed.\n");
        print_error_message(ret);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }
    else if (retval != SGX_SUCCESS)
    {
        print_error_message(retval);
        int len = strlen(ERRORMSG_SGX_ERROR);
        offset = 0;
        memcpy(responseMsg + offset, "0103", 4);
        offset += 4;
        sprintf((char *)(responseMsg + offset), "%04d", len);
        offset += 4;
        memcpy(responseMsg + offset, ERRORMSG_SGX_ERROR, len);
        offset += len;
        (*p_responseMsgLength) = offset;
        return -2;
    }

    // sgx_destroy_enclave(global_eid);
    // add return msg
    offset = 0;
    memcpy(responseMsg + offset, "0000", 4);
    offset += 4;
    sprintf((char *)(responseMsg + offset), "%04d", (sizeof(ek_TEE) + 4));
    offset += 4;
    sprintf((char *)(responseMsg + offset), "%04d", sizeof(ek_TEE));
    offset += 4;
    memcpy(responseMsg + offset, ek_TEE, sizeof(ek_TEE));
    offset += sizeof(ek_TEE);
    (*p_responseMsgLength) = offset;

    printf("handleRequest1002 succeeded.\n");
    return 0;
}

int access_control(char *user_id, char *file_id)
{
    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    printf("===========start t_sgxssl_call_apis==============\n");
    sgx_status_t status = t_sgxssl_call_apis(global_eid);
    if (status != SGX_SUCCESS)
    {
        printf("Call to t_list_built_in_curves has failed.\n");
        return 1; // Test failed
    }
    printf("===========end t_sgxssl_call_apis==============\n");

    printf("===========start t_list_built_in_curves==============\n");
    sgx_status_t status1 = t_list_built_in_curves(global_eid);
    if (status1 != SGX_SUCCESS)
    {
        printf("Call to t_list_built_in_curves has failed.\n");
        return 1; // Test failed
    }
    printf("===========end t_list_built_in_curves==============\n");

    printf("===========start addTest==============\n");
    addTest();
    printf("===========end addTest==============\n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("Info: SampleEnclave successfully returned.\n");

    // printf("Enter a character before exit ...\n");
    // getchar();
    return 0;
}

int access_control_file(int fd, char *user_id, char *file_id)
{
    char filename[MAX_MSG];
    char buf[BUF_SIZE]; /*#defineINET_ADDRSTRLEN16*/
    char buf_out[BUF_SIZE_SMALL];
    memset(filename, 0x00, sizeof(filename));
    memcpy(filename, file_id, strlen(file_id));
    int totalReadBytes = 0;
    int totalWriteBytes = 0;
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        printf("Cannot open file!\n");
        // 出现错误
        Write(fd, "0001", 4);
        memset(buf, 0x00, sizeof(buf));
        strcpy(buf, "open file error");
        Write(fd, buf, strlen(buf));
        return -1;
    }
    else
    {
        /* Initialize the enclave */
        if (initialize_enclave() < 0)
        {
            printf("Enter a character before exit ...\n");
            // 出现错误
            Write(fd, "0002", 4);
            memset(buf, 0x00, sizeof(buf));
            strcpy(buf, "initialize_enclave error");
            Write(fd, buf, strlen(buf));
            return -2;
        }
        // 只有前4个是0000的情况，才能下载。
        Write(fd, "0000", 4);
        printf("write to socket 0000\n");
        int nReadCount;
        size_t nWriteCount = 0;

        memset(buf, 0x00, sizeof(buf));
        while ((nReadCount = fread(buf, 1, BUF_SIZE, fp)) > 0)
        {
            // printf("===========start t_ecall_data_deal==============\n");
            // sgx_status_t status = t_ecall_data_in_out(global_eid, buf);
            sgx_status_t status = t_ecall_data_deal(global_eid, &nWriteCount, buf, buf_out);
            if (status != SGX_SUCCESS)
            {
                printf("Call to t_ecall_data_deal has failed.\n");
                return 1; // Test failed
            }
            // printf("===========end t_ecall_data_deal==============\n");
            // printf("read from file %d!\n", nCount);
            // printf("ecall return %d!\n", nWriteCount);
            Write(fd, buf_out, nWriteCount);
            // printf("write to socket %d!\n", nCount);
            memset(buf_out, 0x00, sizeof(buf_out));
            memset(buf, 0x00, sizeof(buf));
            totalReadBytes += nReadCount;
            totalWriteBytes += nWriteCount;
        }
        shutdown(fd, SHUT_WR); // 文件读取完毕，断开输出流，向客户端发送FIN包
        fclose(fp);
        printf("read from file %d!\n", totalReadBytes);
        printf("write to socket %d!\n", totalWriteBytes);
        /* Destroy the enclave */
        sgx_destroy_enclave(global_eid);

        printf("Info: SampleEnclave successfully returned.\n");
    }

    return totalWriteBytes;
}
