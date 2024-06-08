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

/* Test Array Attributes */

#include "sgx_trts.h"
#include "../Enclave.h"
#include "Enclave_t.h"
#include <string.h>
#include <sgx_tgmp.h>
#include "serialize_en.h"


size_t ecall_mpz_add(char *str_a, char *str_b, char *str_c, size_t sz)
{
	if ( sz > 1024 ) 
		return 0;

	/* check if the buffer is allocated outside */
    if (sgx_is_outside_enclave(str_c, sz) != 1)
        return 0;
    mpz_t a, b, c;
	/*
	 * Marshal untrusted values into the enclave so we don't accidentally
	 * leak secrets to untrusted memory.
	 *
	 * This is overkill for the trivial example in this function, but
	 * it's best to develop good coding habits.
	 */

	if ( str_a == NULL || str_b == NULL ) 
		return 0;

	/* Clear the last, serialized result 

	if ( result != NULL ) {
		gmp_free_func(result, NULL);
		result= NULL;
		len_result= 0;
	}*/

	mpz_inits(a, b, c, NULL);

	/* Deserialize */
	if ( mpz_deserialize(&a, str_a) == -1 ) return 0;
	if ( mpz_deserialize(&b, str_b) == -1 ) return 0;
	mpz_add(c, a, b);
	/* Serialize the result  */
	char *result;
	result= mpz_serialize(c);
	if ( result == NULL ) return 0;
    size_t c_len;
	c_len= strlen(result);
	strncpy(str_c, result, c_len); 
    str_c[c_len]= '\0';
    mpz_clears(a, b, c, NULL);
	return c_len;
	
}
