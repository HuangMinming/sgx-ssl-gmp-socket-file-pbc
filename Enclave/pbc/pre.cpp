

#include "../Enclave.h"
#include "../Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include <sgx_trts.h>
#include "pbc.h"
#include "pre.h"
#include <sgx_tgmp.h>

#define ADD_ENTROPY_SIZE 32
#define RANDOM_BIT_LEN 128

pairing_t pairing;
element_t g; // random generators g ∈ G1
element_t Z; // Z = e(g,g) ∈ GT  Z = e(g,g) ∈ GT
void t_sgxpbc_pairing_init()
{

    // sgx_printf("****start\n");
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
}

void t_sgxpbc_pairing_generate_g_Z()
{

    // Initialize elements
    element_init_G1(g, pairing);

    element_random(g);

    element_init_GT(Z, pairing);

    pairing_apply(Z, g, g, pairing); // e(g,g)
}

void t_sgxpbc_pairing_destroy()
{
    element_clear(g);
    element_clear(Z);
    pairing_clear(pairing);
}

int t_Key_Generation(unsigned char *ptr_a1, size_t ptr_a1_len,
                     unsigned char *ptr_a2, size_t ptr_a2_len,
                     unsigned char *ptr_Z_a1, size_t ptr_Z_a1_len,
                     unsigned char *ptr_g_a2, size_t ptr_g_a2_len)
{
    // mpz_t p, big_prime;
    // mpz_t a1;
    // mpz_t a2;

    // mpz_inits(p, big_prime, a1, a2, NULL);

    // gmp_randstate_t gmp_rand;
    // gmp_randinit_default(gmp_rand);

    // mpz_rrandomb(p, gmp_rand, RANDOM_BIT_LEN);

    // mpz_nextprime(p, big_prime);

    // mpz_add_ui(big_prime, big_prime, 1);

    // mpz_urandomm(a1, gmp_rand, big_prime);
    // mpz_urandomm(a2, gmp_rand, big_prime);

    // mpz_clears(p, big_prime, a1, a2, NULL);

    element_t a1;
    element_t a2;
    element_init_Zr(a1, pairing);
    element_init_Zr(a2, pairing);
    element_random(a1);
    element_random(a2);

    element_t Z_a1;
    element_t g_a2;
    element_init_GT(Z_a1, pairing);
    element_init_G1(g_a2, pairing);

    element_pow_zn(Z_a1, Z, a1);
    element_pow_zn(g_a2, g, a2);

    size_t a1_len = element_length_in_bytes(a1);
    size_t a2_len = element_length_in_bytes(a2);
    size_t Z_a1_len = element_length_in_bytes(Z_a1);
    size_t g_a2_len = element_length_in_bytes(g_a2);

    if (a1_len != ZR_ELEMENT_LENGTH_IN_BYTES ||
        a2_len != ZR_ELEMENT_LENGTH_IN_BYTES ||
        Z_a1_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        g_a2_len != G1_ELEMENT_LENGTH_IN_BYTES)
    {

        sgx_printf("a1_len = %d, ZR_ELEMENT_LENGTH_IN_BYTES = %d\n", a1_len, ZR_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("a2_len = %d, ZR_ELEMENT_LENGTH_IN_BYTES = %d\n", a2_len, ZR_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("Z_a1_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", Z_a1_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("g_a2_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", g_a2_len, G1_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");

        element_clear(a1);
        element_clear(a2);
        element_clear(Z_a1);
        element_clear(g_a2);

        return -1;
    }
    unsigned char a1_data[ZR_ELEMENT_LENGTH_IN_BYTES];
    unsigned char a2_data[ZR_ELEMENT_LENGTH_IN_BYTES];
    unsigned char Z_a1_data[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char g_a2_data[G1_ELEMENT_LENGTH_IN_BYTES];

    sgx_printf("\n a1_data = ");
    element_to_bytes(a1_data, a1);
    for (int i = 0; i < ZR_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", a1_data[i]);
    }
    sgx_printf("\n");

    sgx_printf("\n a2_data = ");
    element_to_bytes(a2_data, a2);
    for (int i = 0; i < ZR_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", a2_data[i]);
    }
    sgx_printf("\n");

    sgx_printf("\n Z_a1_data = ");
    element_to_bytes(Z_a1_data, Z_a1);
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", Z_a1_data[i]);
    }
    sgx_printf("\n");

    sgx_printf("\n g_a2_data = ");
    element_to_bytes(g_a2_data, g_a2);
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", g_a2_data[i]);
    }
    sgx_printf("\n");

    memcpy(ptr_a1, a1_data, ZR_ELEMENT_LENGTH_IN_BYTES);
    memcpy(ptr_a2, a2_data, ZR_ELEMENT_LENGTH_IN_BYTES);
    memcpy(ptr_Z_a1, Z_a1_data, GT_ELEMENT_LENGTH_IN_BYTES);
    memcpy(ptr_g_a2, g_a2_data, G1_ELEMENT_LENGTH_IN_BYTES);

    element_clear(a1);
    element_clear(a2);
    element_clear(Z_a1);
    element_clear(g_a2);

    return 0;
}

int t_Re_Encryption_Key_Generation(unsigned char *ptr_a1, size_t ptr_a1_len,
                                   unsigned char *ptr_g_b2, size_t ptr_g_b2_len,
                                   unsigned char *ptr_rk_A_B, size_t ptr_rk_A_B_len)
{
    element_t a1, g_b2, rk_A_B;
    element_init_Zr(a1, pairing);
    element_init_G1(g_b2, pairing);
    element_init_G1(rk_A_B, pairing);

    element_from_bytes(a1, ptr_a1);
    element_from_bytes(g_b2, ptr_g_b2);

    element_pow_zn(rk_A_B, g_b2, a1);

    size_t rk_A_B_len = element_length_in_bytes(rk_A_B);

    if (rk_A_B_len != G1_ELEMENT_LENGTH_IN_BYTES)
    {
        sgx_printf("rk_A_B_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", rk_A_B_len, G1_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        element_clear(a1);
        element_clear(g_b2);
        element_clear(rk_A_B);

        return -1;
    }

    unsigned char rk_A_B_data[G1_ELEMENT_LENGTH_IN_BYTES];

    sgx_printf("\n rk_A_B_data = ");
    element_to_bytes(rk_A_B_data, g_b2);
    for (int i = 0; i < G1_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", rk_A_B_data[i]);
    }
    sgx_printf("\n");

    memcpy(ptr_rk_A_B, rk_A_B_data, sizeof(rk_A_B_data));

    element_clear(a1);
    element_clear(g_b2);
    element_clear(rk_A_B);

    return 0;
}

int t_GetGTRandom(unsigned char *ptr_m, size_t ptr_m_len)
{
    sgx_printf("t_GetGTRandom start ****\n");
    element_t n, m;
    element_init_GT(m, pairing);
    element_init_GT(n, pairing);

    element_random(n);
    element_random(m);

    size_t m_len = element_length_in_bytes(m);
    if (m_len != GT_ELEMENT_LENGTH_IN_BYTES)
    {
        sgx_printf("m_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", m_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        element_clear(m);
        return -1;
    }

    unsigned char m_data[GT_ELEMENT_LENGTH_IN_BYTES];
    element_to_bytes(m_data, m);
    sgx_printf("\n m_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", m_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_m, m_data, sizeof(m_data));

    element_clear(m);

    element_t m1;
    element_init_GT(m1, pairing);
    element_random(m1);
    unsigned char m1_data[GT_ELEMENT_LENGTH_IN_BYTES];
    element_to_bytes(m1_data, m1);
    sgx_printf("\n m1_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", m1_data[i]);
    }
    sgx_printf("\n");
    element_clear(m1);

    element_t m2;
    element_init_GT(m2, pairing);
    element_random(m2);
    unsigned char m2_data[GT_ELEMENT_LENGTH_IN_BYTES];
    element_to_bytes(m2_data, m2);
    sgx_printf("\n m2_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", m2_data[i]);
    }
    sgx_printf("\n");
    element_clear(m2);


    return 0;
}

int t_Encryption(unsigned char *ptr_m, size_t ptr_m_len,
                 unsigned char *ptr_Z_a1, size_t ptr_Z_a1_len,
                 unsigned char *ptr_a2, size_t ptr_a2_len,
                 unsigned char *ptr_Z_a1_k, size_t ptr_Z_a1_k_len,
                 unsigned char *ptr_m_Z_k, size_t ptr_m_Z_k_len,
                 unsigned char *ptr_Z_a2_k, size_t ptr_Z_a2_k_len,
                 unsigned char *ptr_g_k, size_t ptr_g_k_len,
                 unsigned char *ptr_m_Z_a1_k, size_t ptr_m_Z_a1_k_len)
{
    element_t m, Z_a1, k;
    element_init_GT(m, pairing);
    element_init_GT(Z_a1, pairing);
    element_init_Zr(k, pairing);

    element_from_bytes(m, ptr_m);
    element_from_bytes(Z_a1, ptr_Z_a1);

    element_random(k);

    element_t Z_a1_k, Z_k, m_Z_k;
    element_init_GT(Z_a1_k, pairing);
    element_init_GT(Z_k, pairing);
    element_init_GT(m_Z_k, pairing);

    element_pow_zn(Z_a1_k, Z_a1, k);

    element_pow_zn(Z_k, Z, k);
    element_mul(m_Z_k, m, Z_k);

    element_t a2, Z_a2, Z_a2_k;
    element_init_Zr(a2, pairing);
    element_init_GT(Z_a2, pairing);
    element_init_GT(Z_a2_k, pairing);

    element_from_bytes(a2, ptr_a2);

    element_pow_zn(Z_a2, Z, a2);
    element_pow_zn(Z_a2_k, Z_a2, k);

    element_t g_k, m_Z_a1_k;
    element_init_G1(g_k, pairing);
    element_init_GT(m_Z_a1_k, pairing);

    element_pow_zn(g_k, g, k);

    element_mul(m_Z_a1_k, m, Z_a1_k);

    size_t Z_a1_k_len = element_length_in_bytes(Z_a1_k);
    size_t m_Z_k_len = element_length_in_bytes(m_Z_k);
    size_t Z_a2_k_len = element_length_in_bytes(Z_a2_k);
    size_t g_k_len = element_length_in_bytes(g_k);
    size_t m_Z_a1_k_len = element_length_in_bytes(m_Z_a1_k);

    if (Z_a1_k_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        m_Z_k_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        Z_a2_k_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        g_k_len != G1_ELEMENT_LENGTH_IN_BYTES ||
        m_Z_a1_k_len != GT_ELEMENT_LENGTH_IN_BYTES)
    {
        sgx_printf("Z_a1_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", Z_a1_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("m_Z_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", m_Z_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("Z_a2_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", Z_a2_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("g_k_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", g_k_len, G1_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("m_Z_a1_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", m_Z_a1_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        element_clear(m);
        element_clear(Z_a1);
        element_clear(k);
        element_clear(Z_a1_k);
        element_clear(Z_k);
        element_clear(m_Z_k);
        element_clear(a2);
        element_clear(Z_a2);
        element_clear(Z_a2_k);
        element_clear(g_k);
        element_clear(m_Z_a1_k);
    }

    unsigned char Z_a1_k_data[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char m_Z_k_data[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char Z_a2_k_data[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char g_k_data[G1_ELEMENT_LENGTH_IN_BYTES];
    unsigned char m_Z_a1_k_data[GT_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(Z_a1_k_data, Z_a1_k);
    sgx_printf("\n Z_a1_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", Z_a1_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_Z_a1_k, Z_a1_k_data, sizeof(Z_a1_k_data));

    element_to_bytes(m_Z_k_data, m_Z_k);
    sgx_printf("\n m_Z_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", m_Z_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_m_Z_k, m_Z_k_data, sizeof(m_Z_k_data));

    element_to_bytes(Z_a2_k_data, Z_a2_k);
    sgx_printf("\n Z_a2_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", Z_a2_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_Z_a2_k, Z_a2_k_data, sizeof(Z_a2_k_data));

    element_to_bytes(g_k_data, g_k);
    sgx_printf("\n g_k_data = ");
    for (int i = 0; i < G1_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", g_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_g_k, g_k_data, sizeof(g_k_data));

    element_to_bytes(m_Z_a1_k_data, m_Z_a1_k);
    sgx_printf("\n m_Z_a1_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", m_Z_a1_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_m_Z_a1_k, m_Z_a1_k_data, sizeof(m_Z_a1_k_data));

    element_clear(m);
    element_clear(Z_a1);
    element_clear(k);
    element_clear(Z_a1_k);
    element_clear(Z_k);
    element_clear(m_Z_k);
    element_clear(a2);
    element_clear(Z_a2);
    element_clear(Z_a2_k);
    element_clear(g_k);
    element_clear(m_Z_a1_k);
    return 0;
}

int t_First_Level_Encryption(unsigned char *ptr_m, size_t ptr_m_len,
                             unsigned char *ptr_Z_a1, size_t ptr_Z_a1_len,
                             unsigned char *ptr_a2, size_t ptr_a2_len,
                             unsigned char *ptr_Z_a1_k, size_t ptr_Z_a1_k_len,
                             unsigned char *ptr_m_Z_k, size_t ptr_m_Z_k_len,
                             unsigned char *ptr_Z_a2_k, size_t ptr_Z_a2_k_len)
{
    element_t m, Z_a1, k;
    element_init_GT(m, pairing);
    element_init_GT(Z_a1, pairing);
    element_init_Zr(k, pairing);

    element_from_bytes(m, ptr_m);
    element_from_bytes(Z_a1, ptr_Z_a1);
    element_random(k);

    element_t Z_a1_k, Z_k, m_Z_k;
    element_init_GT(Z_a1_k, pairing);
    element_init_GT(Z_k, pairing);
    element_init_GT(m_Z_k, pairing);

    element_pow_zn(Z_a1_k, Z_a1, k);
    element_pow_zn(Z_k, Z, k);
    element_mul(m_Z_k, m, Z_k);

    element_t a2, Z_a2, Z_a2_k;
    element_init_Zr(a2, pairing);
    element_init_GT(Z_a2, pairing);
    element_init_GT(Z_a2_k, pairing);

    element_from_bytes(a2, ptr_a2);
    element_pow_zn(Z_a2, Z, a2);
    element_pow_zn(Z_a2_k, Z_a2, k);


    size_t Z_a1_k_len = element_length_in_bytes(Z_a1_k);
    size_t m_Z_k_len = element_length_in_bytes(m_Z_k);
    size_t Z_a2_k_len = element_length_in_bytes(Z_a2_k);

    if (Z_a1_k_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        m_Z_k_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        Z_a2_k_len != GT_ELEMENT_LENGTH_IN_BYTES )
    {
        sgx_printf("Z_a1_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", Z_a1_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("m_Z_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", m_Z_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("Z_a2_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", Z_a2_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
         sgx_printf("exit \n");
        element_clear(m);
        element_clear(Z_a1);
        element_clear(k);
        element_clear(Z_a1_k);
        element_clear(Z_k);
        element_clear(m_Z_k);
        element_clear(a2);
        element_clear(Z_a2);
        element_clear(Z_a2_k);
    }

    unsigned char Z_a1_k_data[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char m_Z_k_data[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char Z_a2_k_data[GT_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(Z_a1_k_data, Z_a1_k);
    sgx_printf("\n Z_a1_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", Z_a1_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_Z_a1_k, Z_a1_k_data, sizeof(Z_a1_k_data));

    element_to_bytes(m_Z_k_data, m_Z_k);
    sgx_printf("\n m_Z_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", m_Z_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_m_Z_k, m_Z_k_data, sizeof(m_Z_k_data));

    element_to_bytes(Z_a2_k_data, Z_a2_k);
    sgx_printf("\n Z_a2_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", Z_a2_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_Z_a2_k, Z_a2_k_data, sizeof(Z_a2_k_data));

    element_clear(m);
    element_clear(Z_a1);
    element_clear(k);
    element_clear(Z_a1_k);
    element_clear(Z_k);
    element_clear(m_Z_k);
    element_clear(a2);
    element_clear(Z_a2);
    element_clear(Z_a2_k);
    return 0;
}

int t_Second_Level_Encryption(unsigned char *ptr_m, size_t ptr_m_len,
                 unsigned char *ptr_Z_a1, size_t ptr_Z_a1_len,
                 unsigned char *ptr_g_k, size_t ptr_g_k_len,
                 unsigned char *ptr_m_Z_a1_k, size_t ptr_m_Z_a1_k_len)
{
    element_t m, Z_a1, k;
    element_init_GT(m, pairing);
    element_init_GT(Z_a1, pairing);
    element_init_Zr(k, pairing);

    element_from_bytes(m, ptr_m);
    element_from_bytes(Z_a1, ptr_Z_a1);
    element_random(k);

    element_t g_k, Z_a1_k, m_Z_a1_k;
    element_init_G1(g_k, pairing);
    element_init_GT(Z_a1_k, pairing);
    element_init_GT(m_Z_a1_k, pairing);

    element_pow_zn(g_k, g, k);
    element_pow_zn(Z_a1_k, Z_a1, k);
    element_mul(m_Z_a1_k, m, Z_a1_k);

    size_t g_k_len = element_length_in_bytes(g_k);
    size_t m_Z_a1_k_len = element_length_in_bytes(m_Z_a1_k);
    if (g_k_len != G1_ELEMENT_LENGTH_IN_BYTES ||
        m_Z_a1_k_len != GT_ELEMENT_LENGTH_IN_BYTES)
    {
        sgx_printf("g_k_len = %d, G1_ELEMENT_LENGTH_IN_BYTES = %d\n", g_k_len, G1_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("m_Z_a1_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", m_Z_a1_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        element_clear(m);
        element_clear(Z_a1);
        element_clear(k);
        element_clear(Z_a1_k);
        element_clear(g_k);
        element_clear(m_Z_a1_k);
    }

    unsigned char g_k_data[G1_ELEMENT_LENGTH_IN_BYTES];
    unsigned char m_Z_a1_k_data[GT_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(g_k_data, g_k);
    sgx_printf("\n g_k_data = ");
    for (int i = 0; i < G1_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", g_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_g_k, g_k_data, sizeof(g_k_data));

    element_to_bytes(m_Z_a1_k_data, m_Z_a1_k);
    sgx_printf("\n m_Z_a1_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", m_Z_a1_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_m_Z_a1_k, m_Z_a1_k_data, sizeof(m_Z_a1_k_data));

    element_clear(m);
    element_clear(Z_a1);
    element_clear(k);
    element_clear(Z_a1_k);
    element_clear(g_k);
    element_clear(m_Z_a1_k);
    return 0;
}

int t_Re_Encryption(unsigned char *ptr_g_k, size_t ptr_g_k_len,
                    unsigned char *ptr_rk_A_B, size_t ptr_rk_A_B_len,
                    unsigned char *ptr_m_Z_a1_k, size_t ptr_m_Z_a1_k_len,
                    unsigned char *ptr_Z_b2_a1_k, size_t ptr_Z_b2_a1_k_len)
{

    element_t g_k, rk_A_B, m_Z_a1_k, Z_b2_a1_k;

    element_init_G1(g_k, pairing);
    element_init_G1(rk_A_B, pairing);
    element_init_GT(m_Z_a1_k, pairing);
    element_init_GT(Z_b2_a1_k, pairing);

    element_from_bytes(g_k, ptr_g_k);
    element_from_bytes(rk_A_B, ptr_rk_A_B);
    element_from_bytes(m_Z_a1_k, ptr_m_Z_a1_k);

    pairing_apply(Z_b2_a1_k, g_k, rk_A_B, pairing);

    size_t Z_b2_a1_k_len = element_length_in_bytes(Z_b2_a1_k);
    if (Z_b2_a1_k_len != GT_ELEMENT_LENGTH_IN_BYTES)
    {
        sgx_printf("Z_b2_a1_k_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", Z_b2_a1_k_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        element_clear(g_k);
        element_clear(rk_A_B);
        element_clear(m_Z_a1_k);
        element_clear(Z_b2_a1_k);
        return -1;
    }

    unsigned char Z_b2_a1_k_data[GT_ELEMENT_LENGTH_IN_BYTES];
    element_to_bytes(Z_b2_a1_k_data, Z_b2_a1_k);
    sgx_printf("\n Z_b2_a1_k_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", Z_b2_a1_k_data[i]);
    }
    sgx_printf("\n");
    memcpy(ptr_Z_b2_a1_k, Z_b2_a1_k_data, sizeof(Z_b2_a1_k_data));

    element_clear(g_k);
    element_clear(rk_A_B);
    element_clear(m_Z_a1_k);
    element_clear(Z_b2_a1_k);
    return 0;
}

int t_First_Level_Decryption(unsigned char *ptr_Z_a1_k, size_t ptr_Z_a1_k_len,
                             unsigned char *ptr_m_Z_k, size_t ptr_m_Z_k_len,
                             unsigned char *ptr_Z_a2_k, size_t ptr_Z_a2_k_len,
                             unsigned char *ptr_a1, size_t ptr_a1_len,
                             unsigned char *ptr_a2, size_t ptr_a2_len)
{

    element_t Z_a1_k, m_Z_k, Z_a2_k, a1, a2;

    element_init_GT(Z_a1_k, pairing);
    element_init_GT(m_Z_k, pairing);
    element_init_GT(Z_a2_k, pairing);
    element_init_Zr(a1, pairing);
    element_init_Zr(a2, pairing);

    element_from_bytes(Z_a1_k, ptr_Z_a1_k);
    element_from_bytes(m_Z_k, ptr_m_Z_k);
    element_from_bytes(Z_a2_k, ptr_Z_a2_k);
    element_from_bytes(a1, ptr_a1);
    element_from_bytes(a2, ptr_a2);

    element_t a1_invert, a2_invert, alpha_a1_invert, alpha_a2_invert;
    element_t beta_alpha_a1_invert, beta_alpha_a2_invert;

    element_init_Zr(a1_invert, pairing);
    element_init_Zr(a2_invert, pairing);
    element_init_GT(alpha_a1_invert, pairing);
    element_init_GT(alpha_a2_invert, pairing);
    element_init_GT(beta_alpha_a1_invert, pairing);
    element_init_GT(beta_alpha_a2_invert, pairing);

    element_invert(a1_invert, a1);
    element_invert(a2_invert, a2);

    element_pow_zn(alpha_a1_invert, Z_a1_k, a1_invert);
    element_pow_zn(alpha_a2_invert, Z_a2_k, a2_invert);

    element_div(beta_alpha_a1_invert, m_Z_k, alpha_a1_invert);
    element_div(beta_alpha_a2_invert, m_Z_k, alpha_a2_invert);

    size_t beta_alpha_a1_invert_len = element_length_in_bytes(beta_alpha_a1_invert);
    size_t beta_alpha_a2_invert_len = element_length_in_bytes(beta_alpha_a2_invert);
    if (beta_alpha_a1_invert_len != GT_ELEMENT_LENGTH_IN_BYTES ||
        beta_alpha_a2_invert_len != GT_ELEMENT_LENGTH_IN_BYTES)
    {
        sgx_printf("beta_alpha_a1_invert_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", beta_alpha_a1_invert_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("beta_alpha_a2_invert_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", beta_alpha_a2_invert_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        element_clear(Z_a1_k);
        element_clear(m_Z_k);
        element_clear(Z_a2_k);
        element_clear(a1);
        element_clear(a2);
        element_clear(a1_invert);
        element_clear(a2_invert);
        element_clear(alpha_a1_invert);
        element_clear(alpha_a2_invert);
        element_clear(beta_alpha_a1_invert);
        element_clear(beta_alpha_a2_invert);
        return -1;
    }

    unsigned char beta_alpha_a1_invert_data[GT_ELEMENT_LENGTH_IN_BYTES];
    unsigned char beta_alpha_a2_invert_data[GT_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(beta_alpha_a1_invert_data, beta_alpha_a1_invert);
    sgx_printf("\n beta_alpha_a1_invert_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", beta_alpha_a1_invert_data[i]);
    }
    sgx_printf("\n");

    element_to_bytes(beta_alpha_a2_invert_data, beta_alpha_a2_invert);
    sgx_printf("\n beta_alpha_a2_invert_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", beta_alpha_a2_invert_data[i]);
    }
    sgx_printf("\n");

    element_clear(Z_a1_k);
    element_clear(m_Z_k);
    element_clear(Z_a2_k);
    element_clear(a1);
    element_clear(a2);
    element_clear(a1_invert);
    element_clear(a2_invert);
    element_clear(alpha_a1_invert);
    element_clear(alpha_a2_invert);
    element_clear(beta_alpha_a1_invert);
    element_clear(beta_alpha_a2_invert);
    return 0;
}

int t_Second_Level_Decryption(unsigned char *ptr_g_k, size_t ptr_g_k_len,
                              unsigned char *ptr_m_Z_a1_k, size_t ptr_m_Z_a1_k_len,
                              unsigned char *ptr_a1, size_t ptr_a1_len)
{
    element_t g_k, m_Z_a1_k, a1;
    element_init_G1(g_k, pairing);
    element_init_GT(m_Z_a1_k, pairing);
    element_init_Zr(a1, pairing);

    element_from_bytes(g_k, ptr_g_k);
    element_from_bytes(m_Z_a1_k, ptr_m_Z_a1_k);
    element_from_bytes(a1, ptr_a1);

    element_t pair_alpha_g, pair_alpha_g_a1, beta_pair_alpha_g_a1;
    element_init_GT(pair_alpha_g, pairing);
    element_init_GT(pair_alpha_g_a1, pairing);
    element_init_GT(beta_pair_alpha_g_a1, pairing);
    pairing_apply(pair_alpha_g, g_k, g, pairing);
    element_pow_zn(pair_alpha_g_a1, pair_alpha_g, a1);
    element_div(beta_pair_alpha_g_a1, m_Z_a1_k, pair_alpha_g_a1);

    size_t beta_pair_alpha_g_a1_len = element_length_in_bytes(beta_pair_alpha_g_a1);
    if (beta_pair_alpha_g_a1_len != GT_ELEMENT_LENGTH_IN_BYTES)
    {
        sgx_printf("beta_pair_alpha_g_a1_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", beta_pair_alpha_g_a1_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        element_clear(g_k);
        element_clear(m_Z_a1_k);
        element_clear(a1);
        element_clear(pair_alpha_g);
        element_clear(pair_alpha_g_a1);
        element_clear(beta_pair_alpha_g_a1);

        return -1;
    }

    unsigned char beta_pair_alpha_g_a1_data[GT_ELEMENT_LENGTH_IN_BYTES];
    element_to_bytes(beta_pair_alpha_g_a1_data, beta_pair_alpha_g_a1);
    sgx_printf("\n beta_pair_alpha_g_a1_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", beta_pair_alpha_g_a1_data[i]);
    }
    sgx_printf("\n");
    element_clear(g_k);
    element_clear(m_Z_a1_k);
    element_clear(a1);
    element_clear(pair_alpha_g);
    element_clear(pair_alpha_g_a1);
    element_clear(beta_pair_alpha_g_a1);
    return 0;
}

int t_B_Decryption(
    unsigned char *ptr_m_Z_a1_k, size_t ptr_m_Z_a1_k_len,
    unsigned char *ptr_Z_b2_a1_k, size_t ptr_Z_b2_a1_k_len,
    unsigned char *ptr_b2, size_t ptr_b2_len
    ) 
{
    element_t m_Z_a1_k, Z_b2_a1_k, b2;

    element_init_GT(m_Z_a1_k, pairing);
    element_init_GT(Z_b2_a1_k, pairing);
    element_init_Zr(b2, pairing);

    element_from_bytes(m_Z_a1_k, ptr_m_Z_a1_k);
    element_from_bytes(Z_b2_a1_k, ptr_Z_b2_a1_k);
    element_from_bytes(b2, ptr_b2);

    element_t b2_invert, alpha_b2_invert, beta_alpha_b2_invert;

    element_init_Zr(b2_invert, pairing);
    element_init_GT(alpha_b2_invert, pairing);
    element_init_GT(beta_alpha_b2_invert, pairing);

    element_invert(b2_invert, b2);
    element_pow_zn(alpha_b2_invert, Z_b2_a1_k, b2_invert);
    element_div(beta_alpha_b2_invert, m_Z_a1_k, alpha_b2_invert);

    size_t beta_alpha_b2_invert_len = element_length_in_bytes(beta_alpha_b2_invert);
    if (beta_alpha_b2_invert_len != GT_ELEMENT_LENGTH_IN_BYTES )
    {
        sgx_printf("beta_alpha_b2_invert_len = %d, GT_ELEMENT_LENGTH_IN_BYTES = %d\n", beta_alpha_b2_invert_len, GT_ELEMENT_LENGTH_IN_BYTES);
        sgx_printf("exit \n");
        
        // element_clear(beta_alpha_a2_invert);
        return -1;
    }

    unsigned char beta_alpha_b2_invert_data[GT_ELEMENT_LENGTH_IN_BYTES];

    element_to_bytes(beta_alpha_b2_invert_data, beta_alpha_b2_invert);
    sgx_printf("\n beta_alpha_b2_invert_data = ");
    for (int i = 0; i < GT_ELEMENT_LENGTH_IN_BYTES; i++)
    {
        sgx_printf("%02x", beta_alpha_b2_invert_data[i]);
    }
    sgx_printf("\n");

    // element_clear(beta_alpha_a2_invert);
    return 0;

}

void t_sgxpbc_call_apis(unsigned char *ptr1, size_t len1, unsigned char *ptr2, size_t len2)
{
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
    element_pow_zn(pk, g, sk);        // g^x

    // Verify signature
    element_t e1, e2;
    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);

    pairing_apply(e1, signature, g, pairing); // e(signature,g)
    pairing_apply(e2, h, pk, pairing);        // e(h,g^x)

    if (element_cmp(e1, e2) == 0)
    {
        sgx_printf("Signature verified successfully.\n");
    }
    else
    {
        sgx_printf("Failed to verify signature.\n");
    }

    size_t n1 = element_length_in_bytes(e1);
    unsigned char *data1 = (unsigned char *)malloc(n1);
    sgx_printf("n1 = %d.\n data1 = ", n1);
    element_to_bytes(data1, e1);
    for (int i = 0; i < n1; i++)
    {
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
    for (int i = 0; i < n2; i++)
    {
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

void t_sgxpbc_call_free_pairing()
{
    pairing_clear(pairing);
}

void t_sgxpbc_call_test(unsigned char *ptr1, size_t len1, unsigned char *ptr2, size_t len2)
{

    element_t e3, e4;
    element_init_GT(e3, pairing);
    element_init_GT(e4, pairing);
    element_from_bytes(e3, ptr1);
    element_from_bytes(e4, ptr2);
    if (element_cmp(e3, e4) == 0)
    {
        sgx_printf("e3 == e4.\n");
    }
    else
    {
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
    element_pow_zn(pk, g, sk);        // g^x

    // Verify signature
    element_t e1, e2;
    element_init_GT(e1, pairing);
    element_init_GT(e2, pairing);

    pairing_apply(e1, signature, g, pairing); // e(signature,g)
    pairing_apply(e2, h, pk, pairing);        // e(h,g^x)

    if (element_cmp(e1, e2) == 0)
    {
        sgx_printf("Signature verified successfully.\n");
    }
    else
    {
        sgx_printf("Failed to verify signature.\n");
    }

    size_t n1 = element_length_in_bytes(e1);
    unsigned char *data1 = (unsigned char *)malloc(n1);
    sgx_printf("n1 = %d.\n data1 = ", n1);
    element_to_bytes(data1, e1);
    for (int i = 0; i < n1; i++)
    {
        sgx_printf("%02x ", data1[i]);
    }
    sgx_printf("\n");

    size_t n2 = element_length_in_bytes(e2);
    unsigned char *data2 = (unsigned char *)malloc(n2);
    sgx_printf("n2 = %d.\n data2 = ", n2);
    element_to_bytes(data2, e2);
    for (int i = 0; i < n2; i++)
    {
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
    if (element_cmp(e3, e4) == 0)
    {
        sgx_printf("e3 == e4.\n");
    }
    else
    {
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
