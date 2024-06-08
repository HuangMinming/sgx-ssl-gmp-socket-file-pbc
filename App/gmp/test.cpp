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


#include "../App.h"
#include "Enclave_u.h"
#include "test.h"


void addTest()
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    
    mpz_t a, b, c;
    mpz_inits(a, b, c, NULL);
    mpz_set_si(a, 100);
    mpz_set_si(b, 200);
    char *str_a, *str_b;
    char str_c[1024];
    str_a= mpz_serialize(a);
	str_b= mpz_serialize(b);
	if ( str_a == NULL || str_b == NULL ) {
		fprintf(stderr, "could not convert mpz to string");
		return;
	}
    /* Add the numbers */

    size_t len = 0;
	ret= ecall_mpz_add(global_eid, &len, str_a, str_b, str_c, 1024);
	if ( ret != SGX_SUCCESS ) {
		fprintf(stderr, "ECALL test_mpz_add_ui: 0x%04x\n", ret);
		return;
	}
    if ( len == 0 ) {
		fprintf(stderr, "e_get_result: bad parameters\n");
		return ;
	}
    
	
    if ( mpz_deserialize(&c, str_c) == -1 ) {
		fprintf(stderr, "mpz_deserialize: bad integer string\n");
		return;
	}

	gmp_printf("iadd : %Zd + %Zd = %Zd\n\n", a, b, c);
}
