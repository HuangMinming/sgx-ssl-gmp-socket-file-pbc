
#include "../Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "tSgxSSL_api.h"
#include "ssl.h"

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <openssl/aes.h>

#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <openssl/ecdh.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>

const int DEBUG = 0;


void rsa_key_gen()
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
    {
        sgx_printf("EVP_PKEY_CTX_new_id: %ld\n", ERR_get_error());
        return;
    }
    int ret = EVP_PKEY_keygen_init(ctx);
    if (!ret)
    {
        sgx_printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0)
    {
        sgx_printf("EVP_PKEY_CTX_set_rsa_keygen_bits: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY* evp_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (EVP_PKEY_keygen(ctx, &evp_pkey) <= 0)
#else //new API EVP_PKEY_generate() since 3.0
    if (EVP_PKEY_generate(ctx, &evp_pkey) <= 0)
#endif
    {
        sgx_printf("EVP_PKEY_keygen: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    // public key - string
    int len = i2d_PublicKey(evp_pkey, NULL);
    unsigned char *buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        sgx_printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    unsigned char *tbuf = buf;
    i2d_PublicKey(evp_pkey, &tbuf);

    // print public key
    // printf ("{\"public\":\"");
    int i;
    for (i = 0; i < len; i++) {
        sgx_printf("%02x", (unsigned char) buf[i]);
    }
    sgx_printf("\"}\n");

    free(buf);

    // private key - string
    len = i2d_PrivateKey(evp_pkey, NULL);
    buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        sgx_printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    tbuf = buf;
    i2d_PrivateKey(evp_pkey, &tbuf);

    // print private key
    // printf ("{\"private\":\"");
    for (i = 0; i < len; i++) {
        sgx_printf("%02x", (unsigned char) buf[i]);
    }
    sgx_printf("\"}\n");

    free(buf);

    EVP_PKEY_free(evp_pkey);
}

void ec_key_gen()
{
    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx)
    {
        sgx_printf("EVP_PKEY_CTX_new_id: %ld\n", ERR_get_error());
        return;
    }
    int ret = EVP_PKEY_keygen_init(ctx);
    if (!ret)
    {
        sgx_printf("EVP_PKEY_keygen_init: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_secp384r1) <= 0)
    {
        sgx_printf("EVP_PKEY_CTX_set_ec_paramgen_curve_nid: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    EVP_PKEY* ec_pkey = NULL;
#if OPENSSL_VERSION_NUMBER < 0x30000000
    if (EVP_PKEY_keygen(ctx, &ec_pkey) <= 0)
#else //new API EVP_PKEY_generate() since 3.0
    if (EVP_PKEY_generate(ctx, &ec_pkey) <= 0)
#endif
    {
        sgx_printf("EVP_PKEY_keygen: %ld\n", ERR_get_error());
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    // public key - string
    int len = i2d_PublicKey(ec_pkey, NULL);
    unsigned char *buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        sgx_printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    unsigned char *tbuf = buf;
    i2d_PublicKey(ec_pkey, &tbuf);

    // print public key
    sgx_printf("{\"public\":\"");
    int i;
    for (i = 0; i < len; i++) {
        sgx_printf("%02x", (unsigned char) buf[i]);
    }
    sgx_printf("\"}\n");

    free(buf);

    // private key - string
    len = i2d_PrivateKey(ec_pkey, NULL);
    buf = (unsigned char *) malloc (len + 1);
    if (!buf)
    {
        sgx_printf("Failed in calling malloc()\n");
        EVP_PKEY_CTX_free(ctx);
        return;
    }
    tbuf = buf;
    i2d_PrivateKey(ec_pkey, &tbuf);

    // print private key
    sgx_printf("{\"private\":\"");
    for (i = 0; i < len; i++) {
        sgx_printf("%02x", (unsigned char) buf[i]);
    }
    sgx_printf("\"}\n");

    free(buf);

    EVP_PKEY_free(ec_pkey);
}

# define SetKey \
    RSA_set0_key(key,                                           \
                 BN_bin2bn(n, sizeof(n)-1, NULL),               \
                 BN_bin2bn(e, sizeof(e)-1, NULL),               \
                 BN_bin2bn(d, sizeof(d)-1, NULL));              \
    RSA_set0_factors(key,                                       \
                     BN_bin2bn(p, sizeof(p)-1, NULL),           \
                     BN_bin2bn(q, sizeof(q)-1, NULL));          \
    RSA_set0_crt_params(key,                                    \
                        BN_bin2bn(dmp1, sizeof(dmp1)-1, NULL),  \
                        BN_bin2bn(dmq1, sizeof(dmq1)-1, NULL),  \
                        BN_bin2bn(iqmp, sizeof(iqmp)-1, NULL)); \
    memcpy(c, ctext_ex, sizeof(ctext_ex) - 1);                  \
    return (sizeof(ctext_ex) - 1);

static int key1(RSA *key, unsigned char *c)
{
    static unsigned char n[] =
        "\x00\xAA\x36\xAB\xCE\x88\xAC\xFD\xFF\x55\x52\x3C\x7F\xC4\x52\x3F"
        "\x90\xEF\xA0\x0D\xF3\x77\x4A\x25\x9F\x2E\x62\xB4\xC5\xD9\x9C\xB5"
        "\xAD\xB3\x00\xA0\x28\x5E\x53\x01\x93\x0E\x0C\x70\xFB\x68\x76\x93"
        "\x9C\xE6\x16\xCE\x62\x4A\x11\xE0\x08\x6D\x34\x1E\xBC\xAC\xA0\xA1"
        "\xF5";

    static unsigned char e[] = "\x11";

    static unsigned char d[] =
        "\x0A\x03\x37\x48\x62\x64\x87\x69\x5F\x5F\x30\xBC\x38\xB9\x8B\x44"
        "\xC2\xCD\x2D\xFF\x43\x40\x98\xCD\x20\xD8\xA1\x38\xD0\x90\xBF\x64"
        "\x79\x7C\x3F\xA7\xA2\xCD\xCB\x3C\xD1\xE0\xBD\xBA\x26\x54\xB4\xF9"
        "\xDF\x8E\x8A\xE5\x9D\x73\x3D\x9F\x33\xB3\x01\x62\x4A\xFD\x1D\x51";

    static unsigned char p[] =
        "\x00\xD8\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
        "\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x12"
        "\x0D";

    static unsigned char q[] =
        "\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
        "\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
        "\x89";

    static unsigned char dmp1[] =
        "\x59\x0B\x95\x72\xA2\xC2\xA9\xC4\x06\x05\x9D\xC2\xAB\x2F\x1D\xAF"
        "\xEB\x7E\x8B\x4F\x10\xA7\x54\x9E\x8E\xED\xF5\xB4\xFC\xE0\x9E\x05";

    static unsigned char dmq1[] =
        "\x00\x8E\x3C\x05\x21\xFE\x15\xE0\xEA\x06\xA3\x6F\xF0\xF1\x0C\x99"
        "\x52\xC3\x5B\x7A\x75\x14\xFD\x32\x38\xB8\x0A\xAD\x52\x98\x62\x8D"
        "\x51";

    static unsigned char iqmp[] =
        "\x36\x3F\xF7\x18\x9D\xA8\xE9\x0B\x1D\x34\x1F\x71\xD0\x9B\x76\xA8"
        "\xA9\x43\xE1\x1D\x10\xB2\x4D\x24\x9F\x2D\xEA\xFE\xF8\x0C\x18\x26";

    static unsigned char ctext_ex[] =
        "\x1b\x8f\x05\xf9\xca\x1a\x79\x52\x6e\x53\xf3\xcc\x51\x4f\xdb\x89"
        "\x2b\xfb\x91\x93\x23\x1e\x78\xb9\x92\xe6\x8d\x50\xa4\x80\xcb\x52"
        "\x33\x89\x5c\x74\x95\x8d\x5d\x02\xab\x8c\x0f\xd0\x40\xeb\x58\x44"
        "\xb0\x05\xc3\x9e\xd8\x27\x4a\x9d\xbf\xa8\x06\x71\x40\x94\x39\xd2";

    SetKey;
}

static int key2(RSA *key, unsigned char *c)
{
    static unsigned char n[] =
        "\x00\xA3\x07\x9A\x90\xDF\x0D\xFD\x72\xAC\x09\x0C\xCC\x2A\x78\xB8"
        "\x74\x13\x13\x3E\x40\x75\x9C\x98\xFA\xF8\x20\x4F\x35\x8A\x0B\x26"
        "\x3C\x67\x70\xE7\x83\xA9\x3B\x69\x71\xB7\x37\x79\xD2\x71\x7B\xE8"
        "\x34\x77\xCF";

    static unsigned char e[] = "\x3";

    static unsigned char d[] =
        "\x6C\xAF\xBC\x60\x94\xB3\xFE\x4C\x72\xB0\xB3\x32\xC6\xFB\x25\xA2"
        "\xB7\x62\x29\x80\x4E\x68\x65\xFC\xA4\x5A\x74\xDF\x0F\x8F\xB8\x41"
        "\x3B\x52\xC0\xD0\xE5\x3D\x9B\x59\x0F\xF1\x9B\xE7\x9F\x49\xDD\x21"
        "\xE5\xEB";

    static unsigned char p[] =
        "\x00\xCF\x20\x35\x02\x8B\x9D\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92"
        "\xEA\x0D\xA3\xB4\x32\x04\xB5\xCF\xCE\x91";

    static unsigned char q[] =
        "\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
        "\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5F";

    static unsigned char dmp1[] =
        "\x00\x8A\x15\x78\xAC\x5D\x13\xAF\x10\x2B\x22\xB9\x99\xCD\x74\x61"
        "\xF1\x5E\x6D\x22\xCC\x03\x23\xDF\xDF\x0B";

    static unsigned char dmq1[] =
        "\x00\x86\x55\x21\x4A\xC5\x4D\x8D\x4E\xCD\x61\x77\xF1\xC7\x36\x90"
        "\xCE\x2A\x48\x2C\x8B\x05\x99\xCB\xE0\x3F";

    static unsigned char iqmp[] =
        "\x00\x83\xEF\xEF\xB8\xA9\xA4\x0D\x1D\xB6\xED\x98\xAD\x84\xED\x13"
        "\x35\xDC\xC1\x08\xF3\x22\xD0\x57\xCF\x8D";

    static unsigned char ctext_ex[] =
        "\x14\xbd\xdd\x28\xc9\x83\x35\x19\x23\x80\xe8\xe5\x49\xb1\x58\x2a"
        "\x8b\x40\xb4\x48\x6d\x03\xa6\xa5\x31\x1f\x1f\xd5\xf0\xa1\x80\xe4"
        "\x17\x53\x03\x29\xa9\x34\x90\x74\xb1\x52\x13\x54\x29\x08\x24\x52"
        "\x62\x51";

    SetKey;
}

static int key3(RSA *key, unsigned char *c)
{
    static unsigned char n[] =
        "\x00\xBB\xF8\x2F\x09\x06\x82\xCE\x9C\x23\x38\xAC\x2B\x9D\xA8\x71"
        "\xF7\x36\x8D\x07\xEE\xD4\x10\x43\xA4\x40\xD6\xB6\xF0\x74\x54\xF5"
        "\x1F\xB8\xDF\xBA\xAF\x03\x5C\x02\xAB\x61\xEA\x48\xCE\xEB\x6F\xCD"
        "\x48\x76\xED\x52\x0D\x60\xE1\xEC\x46\x19\x71\x9D\x8A\x5B\x8B\x80"
        "\x7F\xAF\xB8\xE0\xA3\xDF\xC7\x37\x72\x3E\xE6\xB4\xB7\xD9\x3A\x25"
        "\x84\xEE\x6A\x64\x9D\x06\x09\x53\x74\x88\x34\xB2\x45\x45\x98\x39"
        "\x4E\xE0\xAA\xB1\x2D\x7B\x61\xA5\x1F\x52\x7A\x9A\x41\xF6\xC1\x68"
        "\x7F\xE2\x53\x72\x98\xCA\x2A\x8F\x59\x46\xF8\xE5\xFD\x09\x1D\xBD"
        "\xCB";

    static unsigned char e[] = "\x11";

    static unsigned char d[] =
        "\x00\xA5\xDA\xFC\x53\x41\xFA\xF2\x89\xC4\xB9\x88\xDB\x30\xC1\xCD"
        "\xF8\x3F\x31\x25\x1E\x06\x68\xB4\x27\x84\x81\x38\x01\x57\x96\x41"
        "\xB2\x94\x10\xB3\xC7\x99\x8D\x6B\xC4\x65\x74\x5E\x5C\x39\x26\x69"
        "\xD6\x87\x0D\xA2\xC0\x82\xA9\x39\xE3\x7F\xDC\xB8\x2E\xC9\x3E\xDA"
        "\xC9\x7F\xF3\xAD\x59\x50\xAC\xCF\xBC\x11\x1C\x76\xF1\xA9\x52\x94"
        "\x44\xE5\x6A\xAF\x68\xC5\x6C\x09\x2C\xD3\x8D\xC3\xBE\xF5\xD2\x0A"
        "\x93\x99\x26\xED\x4F\x74\xA1\x3E\xDD\xFB\xE1\xA1\xCE\xCC\x48\x94"
        "\xAF\x94\x28\xC2\xB7\xB8\x88\x3F\xE4\x46\x3A\x4B\xC8\x5B\x1C\xB3"
        "\xC1";

    static unsigned char p[] =
        "\x00\xEE\xCF\xAE\x81\xB1\xB9\xB3\xC9\x08\x81\x0B\x10\xA1\xB5\x60"
        "\x01\x99\xEB\x9F\x44\xAE\xF4\xFD\xA4\x93\xB8\x1A\x9E\x3D\x84\xF6"
        "\x32\x12\x4E\xF0\x23\x6E\x5D\x1E\x3B\x7E\x28\xFA\xE7\xAA\x04\x0A"
        "\x2D\x5B\x25\x21\x76\x45\x9D\x1F\x39\x75\x41\xBA\x2A\x58\xFB\x65"
        "\x99";

    static unsigned char q[] =
        "\x00\xC9\x7F\xB1\xF0\x27\xF4\x53\xF6\x34\x12\x33\xEA\xAA\xD1\xD9"
        "\x35\x3F\x6C\x42\xD0\x88\x66\xB1\xD0\x5A\x0F\x20\x35\x02\x8B\x9D"
        "\x86\x98\x40\xB4\x16\x66\xB4\x2E\x92\xEA\x0D\xA3\xB4\x32\x04\xB5"
        "\xCF\xCE\x33\x52\x52\x4D\x04\x16\xA5\xA4\x41\xE7\x00\xAF\x46\x15"
        "\x03";

    static unsigned char dmp1[] =
        "\x54\x49\x4C\xA6\x3E\xBA\x03\x37\xE4\xE2\x40\x23\xFC\xD6\x9A\x5A"
        "\xEB\x07\xDD\xDC\x01\x83\xA4\xD0\xAC\x9B\x54\xB0\x51\xF2\xB1\x3E"
        "\xD9\x49\x09\x75\xEA\xB7\x74\x14\xFF\x59\xC1\xF7\x69\x2E\x9A\x2E"
        "\x20\x2B\x38\xFC\x91\x0A\x47\x41\x74\xAD\xC9\x3C\x1F\x67\xC9\x81";

    static unsigned char dmq1[] =
        "\x47\x1E\x02\x90\xFF\x0A\xF0\x75\x03\x51\xB7\xF8\x78\x86\x4C\xA9"
        "\x61\xAD\xBD\x3A\x8A\x7E\x99\x1C\x5C\x05\x56\xA9\x4C\x31\x46\xA7"
        "\xF9\x80\x3F\x8F\x6F\x8A\xE3\x42\xE9\x31\xFD\x8A\xE4\x7A\x22\x0D"
        "\x1B\x99\xA4\x95\x84\x98\x07\xFE\x39\xF9\x24\x5A\x98\x36\xDA\x3D";

    static unsigned char iqmp[] =
        "\x00\xB0\x6C\x4F\xDA\xBB\x63\x01\x19\x8D\x26\x5B\xDB\xAE\x94\x23"
        "\xB3\x80\xF2\x71\xF7\x34\x53\x88\x50\x93\x07\x7F\xCD\x39\xE2\x11"
        "\x9F\xC9\x86\x32\x15\x4F\x58\x83\xB1\x67\xA9\x67\xBF\x40\x2B\x4E"
        "\x9E\x2E\x0F\x96\x56\xE6\x98\xEA\x36\x66\xED\xFB\x25\x79\x80\x39"
        "\xF7";

    static unsigned char ctext_ex[] =
        "\xb8\x24\x6b\x56\xa6\xed\x58\x81\xae\xb5\x85\xd9\xa2\x5b\x2a\xd7"
        "\x90\xc4\x17\xe0\x80\x68\x1b\xf1\xac\x2b\xc3\xde\xb6\x9d\x8b\xce"
        "\xf0\xc4\x36\x6f\xec\x40\x0a\xf0\x52\xa7\x2e\x9b\x0e\xff\xb5\xb3"
        "\xf2\xf1\x92\xdb\xea\xca\x03\xc1\x27\x40\x05\x71\x13\xbf\x1f\x06"
        "\x69\xac\x22\xe9\xf3\xa7\x85\x2e\x3c\x15\xd9\x13\xca\xb0\xb8\x86"
        "\x3a\x95\xc9\x92\x94\xce\x86\x74\x21\x49\x54\x61\x03\x46\xf4\xd4"
        "\x74\xb2\x6f\x7c\x48\xb4\x2e\xe6\x8e\x1f\x57\x2a\x1f\xc4\x02\x6a"
        "\xc4\x56\xb4\xf5\x9f\x7b\x62\x1e\xa1\xb9\xd8\x8f\x64\x20\x2f\xb1";

    SetKey;
}

static int pad_unknown(void)
{
    unsigned long l;
    while ((l = ERR_get_error()) != 0)
        if (ERR_GET_REASON(l) == RSA_R_UNKNOWN_PADDING_TYPE)
            return (1);
    return (0);
}

static const char rnd_seed[] =
    "string to make the random number generator think it has entropy";

int rsa_test()
{
    int err = 0;
    int v;
    RSA *key;
    unsigned char ptext[256];
    unsigned char ctext[256];
    static unsigned char ptext_ex[] = "\x54\x85\x9b\x34\x2c\x49\xea\x2a";
    unsigned char ctext_ex[256];
    int plen;
    int clen = 0;
    int num;
    int n;

    // CRYPTO_set_mem_debug(1);
    // CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RAND_seed(rnd_seed, sizeof rnd_seed); /* or OAEP may fail */

    plen = sizeof(ptext_ex) - 1;

    for (v = 0; v < 3; v++) {
        key = RSA_new();
        switch (v) {
        case 0:
            clen = key1(key, ctext_ex);
            break;
        case 1:
            clen = key2(key, ctext_ex);
            break;
        case 2:
            clen = key3(key, ctext_ex);
            break;
        }
        
        num = RSA_public_encrypt(plen, ptext_ex, ctext, key,
                                 RSA_PKCS1_PADDING);
        if (num != clen) {
            sgx_printf("PKCS#1 v1.5 encryption failed!\n");
            err = 1;
            goto oaep;
        }

        num = RSA_private_decrypt(num, ctext, ptext, key, RSA_PKCS1_PADDING);
        if (num != plen || memcmp(ptext, ptext_ex, num) != 0) {
            sgx_printf("PKCS#1 v1.5 decryption failed!\n");
            err = 1;
        } else
            sgx_printf("PKCS #1 v1.5 encryption/decryption ok\n");

 oaep:
        ERR_clear_error();
        num = RSA_public_encrypt(plen, ptext_ex, ctext, key,
                                 RSA_PKCS1_OAEP_PADDING);
        if (num == -1 && pad_unknown()) {
            sgx_printf("No OAEP support\n");
            goto next;
        }
        if (num != clen) {
            sgx_printf("OAEP encryption failed!\n");
            err = 1;
            goto next;
        }

        num = RSA_private_decrypt(num, ctext, ptext, key,
                                  RSA_PKCS1_OAEP_PADDING);
        if (num != plen || memcmp(ptext, ptext_ex, num) != 0) {
            sgx_printf("OAEP decryption (encrypted data) failed!\n");
            err = 1;
        } else if (memcmp(ctext, ctext_ex, num) == 0)
            sgx_printf("OAEP test vector %d passed!\n", v);

        /*
         * Different ciphertexts (rsa_oaep.c without -DPKCS_TESTVECT). Try
         * decrypting ctext_ex
         */

        num = RSA_private_decrypt(clen, ctext_ex, ptext, key,
                                  RSA_PKCS1_OAEP_PADDING);

        if (num != plen || memcmp(ptext, ptext_ex, num) != 0) {
            sgx_printf("OAEP decryption (test vector data) failed!\n");
            err = 1;
        } else
            sgx_printf("OAEP encryption/decryption ok\n");

        /* Try decrypting corrupted ciphertexts. */
        for (n = 0; n < clen; ++n) {
            ctext[n] ^= 1;
            num = RSA_private_decrypt(clen, ctext, ptext, key,
                                          RSA_PKCS1_OAEP_PADDING);
            if (num > 0) {
                sgx_printf("Corrupt data decrypted!\n");
                err = 1;
                break;
            }
            ctext[n] ^= 1;
        }

        /* Test truncated ciphertexts, as well as negative length. */
        for (n = -1; n < clen; ++n) {
            num = RSA_private_decrypt(n, ctext, ptext, key,
                                      RSA_PKCS1_OAEP_PADDING);
            if (num > 0) {
                sgx_printf("Truncated data decrypted!\n");
                err = 1;
                break;
            }
        }

 next:
        RSA_free(key);
    }

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks_fp(stderr) <= 0)
        err = 1;
#endif

    return err;
}





void t_list_built_in_curves()
{
	EC_builtin_curve *curves = NULL, *p;
	int curves_count, i;
	
	if ( !(curves_count = EC_get_builtin_curves(NULL, 0)) )
	{
		sgx_printf("Get built-in EC curves count failed!\n");
		exit(-1);
	}
	if ( !(curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * curves_count)) )
	{
		sgx_printf("Allocate memory failed!\n");
		exit(-1);
	}
	if ( !(curves_count = EC_get_builtin_curves(curves, curves_count)) )
	{
		sgx_printf("Get built-in EC curves info failed!\n");
		free(curves);
		exit(-1);
	}
	
	 sgx_printf("Total built-in EC curves count: %d\n", curves_count);
	sgx_printf("Built-in EC curves info:\n");
	p = curves;
	for (i = 0; i < curves_count; i++)
	{
		 sgx_printf("EC curve item: %d\n", (i+1));
		 sgx_printf("NID: %d\n", p->nid);
		 sgx_printf("Comment: %s\n", p->comment);
		p++;
	}
	
	free(curves);
}


void t_sgxssl_call_apis()
{
    int ret = 0;
    
    sgx_printf("Start tests\n");
    
    SGXSSLSetPrintToStdoutStderrCB(vprintf_cb);

    //CRYPTO_set_mem_functions(priv_malloc, priv_realloc, priv_free);

    // Initialize SGXSSL crypto
    OPENSSL_init_crypto(0, NULL);

	rsa_key_gen();
    sgx_printf("test rsa_key_gen completed\n");


    ec_key_gen();
    sgx_printf("test ec_key_gen completed\n");
    
	// ret = rsa_test();
    // if (ret != 0)
    // {
    //     sgx_printf("test rsa_test returned error %d\n", ret);
    //     exit(ret);
    // }
    // sgx_printf("test rsa_test completed\n");
    
}



int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new");

    /* Initialise the encryption operation. */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors("EVP_aes_256_gcm");

    /*
     * Set IV length if default 12 bytes (96 bits) is not appropriate
     */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("EVP_CTRL_GCM_SET_IVLEN");

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("EVP_EncryptInit_ex key iv");

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors("EVP_EncryptUpdate");
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors("EVP_EncryptFinal_ex");
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag))
        handleErrors("EVP_CIPHER_CTX_ctrl");

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *tag, int tag_len, unsigned char *key, unsigned char *iv,
                int iv_len, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors("EVP_CIPHER_CTX_new");

    /* Initialise the decryption operation. */
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        handleErrors("EVP_aes_256_gcm");

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        handleErrors("EVP_CTRL_GCM_SET_IVLEN");

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        handleErrors("EVP_DecryptInit_ex key iv");

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors("EVP_DecryptUpdate");
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag))
        handleErrors("EVP_CTRL_GCM_SET_TAG");

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }
    else
    {
        /* Verify failed */
        return -1;
    }
}



void t_sgxssl_test3()
{
    int ret = 0;
    
    sgx_printf("Start t_sgxssl_test\n");
    unsigned char key[KEY_SIZE];
    RAND_bytes(key, KEY_SIZE);

    unsigned char iv[IV_LEN];
    RAND_bytes(iv, IV_LEN);

    unsigned char plaintext[] = "hello world";
    unsigned char plaintext2[BUFSIZ];
    unsigned char ciphertext[BUFSIZ];

    size_t plaintext_len = strlen((const char*)plaintext);

    unsigned char tag[TAG_SIZE *2 ];
    memset(tag, 0x00, sizeof(tag));
    int ciphertext_len =
        gcm_encrypt(plaintext, plaintext_len, key, iv, IV_LEN, ciphertext, tag);

    sgx_printf("ciphertext (len:%d) is:\n", ciphertext_len);
	// BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    sgx_printf("tag (len:%d) is:\n", TAG_SIZE);
	// BIO_dump_fp(stdout, (const char *)tag, TAG_SIZE *2);

    int result =
      gcm_decrypt(ciphertext, ciphertext_len, tag, TAG_SIZE, key, iv, IV_LEN, plaintext2);

    sgx_printf("plaintext2 (len:%d) is:\n", result);
    sgx_printf("%s:\n", plaintext2);
	// BIO_dump_fp(stdout, (const char *)plaintext2, result);
    
    return;
    
    
    
}

void t_sgxssl_test(){
    sgx_printf("Start t_sgxssl_test\n");
    unsigned char key[16] = {0x2b,0x76,0x1d,0xaf,0x10,0x20,0xc0,0x5b,0x90,0xe7,0xeb,0x47,0xf6,0x84,0x4d,0xfa};
    //{0x44,0x14,0x0b,0xa7,0x77,0x7d,0xc5,0xd6,0x5c,0x1f,0x66,0xa7,0xe5,0xe8,0x99,0x44};
    // RAND_bytes(key, 16);
    sgx_printf("key (len:%d) is:\n", 16);
	// BIO_dump_fp(stdout, (const char *)key, 16);

    unsigned char iv[12] = {0x34,0x45,0xf4,0xd8,0xd6,0x4d,0xa8,0x56,0xee,0x47,0x42,0xed};
    //{0xc1,0xdd,0xb6,0x14,0x4a,0x02,0xd3,0x3b,0x64,0x1f,0x8a,0x0a};
    // RAND_bytes(iv, IV_LEN);
    sgx_printf("iv (len:%d) is:\n", 12);
	// BIO_dump_fp(stdout, (const char *)iv, 12);

    // unsigned char plaintext[] = "2234312";
    unsigned char plaintext2[BUFSIZ];
    // unsigned char ciphertext[BUFSIZ];
    unsigned char ciphertext[] = {
        0x53,0x8a,0x9e,0x68,0x25,0x78,0x7b,0x95,
        0xad,0x09,0x40,0xc0,0x92,0x00,0x34,0x91,
        0xa5,0xd8,0x86,0x63,0xfb,0x8d,0x00,0xe6,
        0x65,0xd3,0x47,0xc2,0x3e,0x72,0x6e,0xc4,
        0x0b,0x7f,0xd4,0x3c,0x1e,0x52,0x41,0xed,
        0x3f,0x4b,0xd4,0x80,0x28,0x6b,0xaf,0x93,
        0xfe,0x63,0xf2,0x8a,0x3f,0x9b,0xcb,0x91,
        0x4c,0x75,0x4e,0x29,0x25,0x6b,0xf9,0x24,
        0xc6,0x12,0x5c,0x4f,0x6d,0xdf,0x8f,0x73,
        0x5f,0x85,0xbf,0xc5,0xaf,0x2c,0x1f,0xbb,
        0xf5,0xa9,0xd3,0xbd,0x47,0x2d,0x50,0x92,
        0x63,0xe6,0xa5,0x86,0x04,0xce,0xda,0xd9,
        0xeb,0x56,0x4d,0x64,0xe1,0x44,0xd7,0x8b,
        0x4a,0x95,0xa3,0x4a,0x12,0x9a,0xfb,0xf8,
        0xf5,0x21,0x07,0xfe,0x64,0x82,0x92,0x4e,
        0x2b,0x58,0xb3,0x2b,0xfa,0xed,0xab,0xa3,
        0x99,0x91,0x97,0xad,0x5e,0x62,0x0a,0xdd,
        0x1d,0x91,0xa0,0x88,0xb1,0x6d,0xdc,0x91,
        0xac,0xb2,0xfe,0xd2,0x87,0x0c,0x30,0x2c,
        0x20,0x47,0x7b,0x2b,0xff,0xb2,0x5b,0x2d,
        0xe7,0x03,0xa8,0xb3,0x8d,0xba,0x60,0x7b,
        0x22,0xa2,0xad,0xa4,0x3c,0xe0,0x69,0x10,
        0x01,0x00,0x36,0x56,0x3d,0xc5,0xbc,0x76,
        0xc0,0x50,0xf9,0x52,0x57,0x06,0x06,0x7b,
        0x9b,0xe4,0x8d,0x4b,0x19,0xe7,0x61,0x36,
        0x84,0x50,0x99,0x50,0xb8,0x69,0x10,0xeb,
        0xc1,0xa5,0x60,0x86,0xec,0x70,0x72,0x64,
        0xae,0x67,0x0b,0x66,0x2a,0x95,0x20,0x64,
        0x53,0x48,0x5c,0x0c,0xe3,0x82,0x3e,0x26,
        0x47,0x52,0x32,0xc7,0x79,0xad,0x3e,0x09,
        0x66,0xd3,0x3d,0x6c,0xd2,0xd9,0x25,0xd8,
        0xec,0x58,0x3c,0x4b,0x1f,0x66,0x62,0x33};
    //{0x61,0x24,0x0c,0x1c,0x74,0x5f,0x17};

    // size_t plaintext_len = strlen((const char*)plaintext);

    unsigned char tag[] = {0x47,0x24,0x9b,0xb2,0x1b,0x70,0x7f,0x88,0x11,0xfc,0x6b,0x4c,0xdc,0x7c,0x67,0x5c};
    //{0x5c,0x0b,0x73,0x35,0x7e,0xc5,0x23,0x9f,0xdb,0xff,0xbb,0x01,0x96,0x08,0x40,0x84};
    // unsigned char tag[TAG_SIZE];
    // memset(tag, 0x00, sizeof(tag));
    // int ciphertext_len =
    //     gcm_encrypt(plaintext, plaintext_len, key, iv, IV_LEN, ciphertext, tag);

    // sgx_printf("ciphertext (len:%d) is:\n", sizeof(ciphertext));
	// BIO_dump_fp(stdout, (const char *)ciphertext, sizeof(ciphertext));
    // for(int i=0;i<ciphertext_len;i++) {
    //     sgx_printf("%02X ", ciphertext[i]);
    // }
    // sgx_printf("\n");
    

    // sgx_printf("tag  (len:%d) is:\n", 100);
	// BIO_dump_fp(stdout, (const char *)tag, 100);
    // for(int i=0;i<TAG_SIZE;i++) {
    //     sgx_printf("%02X ", tag[i]);
    // }
    // sgx_printf("\n");

    int result =
      gcm_decrypt(ciphertext, sizeof(ciphertext), tag, TAG_SIZE, key, iv, IV_LEN, plaintext2);

    sgx_printf("plaintext2 (len:%d) is:\n", result);
    for(int i=0;i<result;i++) {
        sgx_printf("%c", plaintext2[i]);
    }
    sgx_printf("\n");
	// BIO_dump_fp(stdout, (const char *)plaintext2, result);

}


void t_sgxssl_ecdsa_test2() {
    char *public_key = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc0oxhhjXfOFZEPR8tadGpv+lwd9Y\n\
CJwqxd9osvTVqjOVlOK04ynnQv6Kj4YPuTWhcDzSqkkgMYA278yY88i+Lg==\n\
-----END PUBLIC KEY-----";
    int public_key_len = strlen(public_key);
    sgx_printf("\npublic_key_len = %d \n", public_key_len);
    sgx_printf("\n%s\n", public_key);
    BIO *verify_bio = NULL;
    verify_bio = BIO_new(BIO_s_mem());
    BIO_puts(verify_bio, public_key);
    EVP_PKEY * veriry_pkey;
    if (NULL == (veriry_pkey = PEM_read_bio_PUBKEY(verify_bio, NULL, NULL, NULL) ))
    {
		BIO_free(verify_bio);
        handleErrors("PEM_read_bio_PUBKEY");
    }

    EVP_MD_CTX *verify_mdctx = EVP_MD_CTX_new();

	// initialize ctx
    EVP_MD_CTX_init(verify_mdctx);
	// verity initialize,  md must be the same as sign
    if(!EVP_VerifyInit_ex(verify_mdctx, EVP_sha256(), NULL))
    {  
		handleErrors("EVP_VerifyInit_ex");
		BIO_free(verify_bio);
		EVP_MD_CTX_free(verify_mdctx);
        return;  
    }  
	// add verify data
    char *msg = "HELLO1";
    if(!EVP_VerifyUpdate(verify_mdctx, msg, strlen(msg)))
    {  
        handleErrors("EVP_VerifyUpdate");
		BIO_free(verify_bio);
		EVP_MD_CTX_free(verify_mdctx);
        return;  
    }     
	// verify
    u_char *sigHex = (u_char*)"304402207145ddb2968068e031d9ff27e7f7579b4c0ebfbc0a4b2d6b7cd51eed63eb2d1902204c5dedbb077ef7bb6a8531162503f7eef9ed72a34b6350bc1e6f9318302007ce";
    int sigHex_len = strlen((const char*)sigHex);
    u_char sig[1024];
    int sig_len = sigHex_len/2;
    HexStrToByteStr(sigHex, sigHex_len, sig);
    sgx_printf("sig:");
    for(int i=0;i<sig_len;i++) {
        sgx_printf("%c", sig[i]);
    }
    sgx_printf("\n");
    sgx_printf("sig[%d] is:\n", sig_len);
    // BIO_dump_fp(stdout, (const char *)sig, sig_len);
    /*
    EVP_VerifyFinal() returns 1 for a correct signature, 
    0 for failure and -1 if some other error occurred.
    */
    int iRet = EVP_VerifyFinal(verify_mdctx,sig,sig_len,veriry_pkey);
    sgx_printf("verify result: %d\n", iRet);
}

void t_sgxssl_ecdsa_test() {
    char *public_key = "-----BEGIN PUBLIC KEY-----\n\
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc0oxhhjXfOFZEPR8tadGpv+lwd9Y\n\
CJwqxd9osvTVqjOVlOK04ynnQv6Kj4YPuTWhcDzSqkkgMYA278yY88i+Lg==\n\
-----END PUBLIC KEY-----";
    int public_key_len = strlen(public_key);
    char *msg = "HELLO";
    u_char *sigHex = (u_char*)"304402207145ddb2968068e031d9ff27e7f7579b4c0ebfbc0a4b2d6b7cd51eed63eb2d1902204c5dedbb077ef7bb6a8531162503f7eef9ed72a34b6350bc1e6f9318302007ce";
    int sigHex_len = strlen((const char*)sigHex);
    int iRet = ecdsa_verify(public_key, public_key_len, msg, strlen(msg), sigHex, sigHex_len);
    sgx_printf("verify result: %d\n", iRet);
}