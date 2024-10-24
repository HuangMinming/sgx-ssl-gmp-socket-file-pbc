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
        std::cout << "Failed to open the file \"" << filename << "\"" << std::endl;
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
        printf("Failed to read the sealed keyPairHe data blob from \" %s \"\n");
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

bool loadSealedData() {

    loadSealed_Vk_Data();
    // loadSealed_bList_U_Data();
    loadSealed_keyPairHex_Data();

    return true;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    printf("*******\n");
    // pairing_test();
    // seal_test();
    // unseal_test();
    // c_pre_test();

    /* Initialize the enclave , set global_eid*/
    if (initialize_enclave() < 0)
    {
        printf("initialize_enclave error, Enter a character before exit ...\n");
        return -2;
    }

    loadSealedData();

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
                    printf("recvMsg is :\n");
                    dump_hex(msg, n, 16);
                    unsigned char responseMsg[BUFSIZ];
                    size_t responseMsgLen;

                    handleRequest(msg, n, i, responseMsg, &responseMsgLen);

                    printf("responseMsg is :\n");
                    if(responseMsgLen > 0) 
                    {
                        dump_hex(responseMsg, responseMsgLen, 16);
                        Write(i, responseMsg, responseMsgLen);
                    }
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
   if(userIdLength <= 0)
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
    if(vk_A_Length <= 0)
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

    printf("userIdLength is %d, userId is :\n", userIdLength);
    dump_hex(userId, userIdLength, 16);
    printf("vk_A_Length is %d, vk_A is :\n", vk_A_Length);
    dump_hex(vk_A, vk_A_Length, 16);

    sgx_status_t retval;
    sgx_status_t ret = t_Admin_Setting(global_eid, &retval, vk_A, vk_A_Length);
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_Admin_Setting failed.\n");
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
    ret = t_get_sealed_vk_A_data_size(global_eid, &sealed_data_size);
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
    ret = t_seal_vk_A_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
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
        printf("Failed to save the sealed data blob to \" %s \" \n");
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
    // set successful respond
    memcpy(responseMsg, "00000000", 8);
    (*p_responseMsgLength) = 8;
    printf("Sealing data succeeded.\n");
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
   if(userIdLength <= 0)
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

    dump_hex(userId, userIdLength, 16);

    sgx_status_t retval;
    unsigned char ek_TEE[G1_ELEMENT_LENGTH_IN_BYTES * 2];
    sgx_status_t ret = t_Trusted_Setup(global_eid, &retval, ek_TEE, sizeof(ek_TEE));
    if (ret != SGX_SUCCESS)
    {
        printf("Call t_Trusted_Setup failed.\n");
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
    ret = t_get_sealed_keyPairHex_data_size(global_eid, &sealed_data_size);
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
    ret = t_seal_keyPairHex_data(global_eid, &retval, temp_sealed_buf, sealed_data_size);
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
        printf("Failed to save the sealed data blob to \" %s \" \n");
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

    printf("Sealing data succeeded.\n");
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
