
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
        return -1;  
    }  
	// add verify data
    if(!EVP_VerifyUpdate(verify_mdctx, msg, msg_len))
    {  
        handleErrors("EVP_VerifyUpdate");
		BIO_free(verify_bio);
		EVP_MD_CTX_free(verify_mdctx);
        return -1;  
    }     
	// verify
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
    sgx_printf("ecdsa_verify verify result: %d\n", iRet);
    return iRet;
}

