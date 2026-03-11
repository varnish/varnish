/*-
 * Copyright (c) 2024 Varnish Software AS
 * All rights reserved.
 *
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
 * Author: Niklas Brand <niklasb@varnish-software.com>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Client-side TLS support
 */

#include <openssl/ssl.h>
#include "vqueue.h"
#include "vtree.h"

/*
 * Per-certificate SSL_CTX wrapper
 */
struct vtls_ctx {
	unsigned 			magic;
#define VTLS_CTX_MAGIC  		0xee1f014c
	SSL_CTX 			*ctx;
	char 				*name_id;
	char				*subject;  /* CN from certificate */
	int				protos;
	int				discarded;
	VTAILQ_ENTRY(vtls_ctx) 		list;
};

/*
 * SNI hostname -> certificate mapping entry
 */
struct vtls_sni_key {
	unsigned			magic;
#define VTLS_SNI_KEY_MAGIC		0x0c6484c4
	char				*id;
	struct vtls_ctx			*ctx;
	unsigned			is_wildcard;
	VTAILQ_HEAD(vtls_sni_key_head, vtls_sni_key)	dups;
	VTAILQ_ENTRY(vtls_sni_key)	dups_list;
	VRBT_ENTRY(vtls_sni_key)		tree;
};
