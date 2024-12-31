
#include "../Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>

#include "tSgxSSL_api.h"

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
const int IV_LEN = 12;
const int TAG_SIZE = 16;
const int KEY_SIZE = 32;

void exit(int status)
{
	usgx_exit(status);
	// Calling to abort function to eliminate warning: ‘noreturn’ function does return [enabled by default]
	abort();
}

void handleErrors(char *x)
{
    if (DEBUG)
    {
        sgx_printf("%s error\n", x);
        // ERR_print_errors_fp(stderr);
    }
    exit(1);
}

/*
returns 1 for a correct signature, 
0 for failure and -1 if some other error occurred.
*/
/*public_key must be NUL-terminated string 
*/
int ecdsa_verify(char * public_key, size_t public_key_len, 
    char *msg, size_t msg_len, 
    u_char *sigHex, size_t sigHex_len) {
    if(public_key[public_key_len] != '\0') {
        sgx_printf("input error, public_key must be NUL-terminated string\n");
        return -1;
    }
#ifdef PRINT_DEBUG_INFO
    sgx_printf("\npublic_key_len = %d \n", public_key_len);
    sgx_printf("\n%s\n", public_key);
#endif
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
        EVP_PKEY_free(veriry_pkey);
		EVP_MD_CTX_free(verify_mdctx);
        return -1;  
    }  
	// add verify data
    if(!EVP_VerifyUpdate(verify_mdctx, msg, msg_len))
    {  
        handleErrors("EVP_VerifyUpdate");
		BIO_free(verify_bio);
        EVP_PKEY_free(veriry_pkey);
		EVP_MD_CTX_free(verify_mdctx);
        return -1;  
    }     
	// verify
    u_char sig[1024];
    int sig_len = sigHex_len/2;
    HexStrToByteStr(sigHex, sigHex_len, sig);
#ifdef PRINT_DEBUG_INFO
    sgx_printf("sig:");
    for(int i=0;i<sig_len;i++) {
        sgx_printf("%c", sig[i]);
    }
    sgx_printf("\n");
    sgx_printf("sig[%d] is:\n", sig_len);
#endif
    // BIO_dump_fp(stdout, (const char *)sig, sig_len);
    /*
    EVP_VerifyFinal() returns 1 for a correct signature, 
    0 for failure and -1 if some other error occurred.
    */
    int iRet = EVP_VerifyFinal(verify_mdctx,sig,sig_len,veriry_pkey);
#ifdef PRINT_DEBUG_INFO
    sgx_printf("ecdsa_verify verify result: %d\n", iRet);
#endif
    BIO_free(verify_bio);
    EVP_PKEY_free(veriry_pkey);
    EVP_MD_CTX_free(verify_mdctx);
    return iRet;
}


int aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
                unsigned char *iv, int iv_len, unsigned char *ciphertext,
                unsigned char *tag, int tag_len)
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
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_CTRL_GCM_SET_IVLEN");
    }

    /* Initialise key and IV */
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_EncryptInit_ex key iv");
    }

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_EncryptUpdate");
    }
    ciphertext_len = len;

    /*
     * Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_EncryptFinal_ex");
    }
    ciphertext_len += len;

    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_CIPHER_CTX_ctrl");
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
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
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_aes_256_gcm");
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_CTRL_GCM_SET_IVLEN");
    }

    /* Initialise key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_DecryptInit_ex key iv");
    }

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_DecryptUpdate");
    }
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
        EVP_CIPHER_CTX_free(ctx);
        handleErrors("EVP_CTRL_GCM_SET_TAG");
    }

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


int getDigestValue(char *digestName, char *message, 
    unsigned char *digestValue, size_t digestValue_len) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    // if(digestValue_len < MD5_LENGTH) {
    //     printf("MD5Value_len too small %d\n", MD5Value_len);
    //     return -1;
    // }
    unsigned int md_len, i;
    md = EVP_get_digestbyname(digestName);

    if (md == NULL) {
        sgx_printf("Unknown message digest %s\n", digestName);
        return -1;
    }

    mdctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex(mdctx, md, NULL)) {
        sgx_printf("Message digest initialization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (!EVP_DigestUpdate(mdctx, message, strlen(message))) {
        sgx_printf("Message digest update failed.\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (!EVP_DigestFinal_ex(mdctx, digestValue, &md_len)) {
        sgx_printf("Message digest finalization failed.\n");
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    if(md_len > digestValue_len) {
        EVP_MD_CTX_free(mdctx);
        sgx_printf("md_len (result of md5) too big %d\n", md_len);
        return -1;
    }
    sgx_printf("Digest(%d) is: ", md_len);
    for (i = 0; i < md_len; i++)
        sgx_printf("%02x", digestValue[i]);
    sgx_printf("\n");
}

