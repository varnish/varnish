/*-
 * Copyright (c) 2019 Varnish Software AS
 * All rights reserved.
 *
 * Author: Niklas Brand <niklasb@varnish-software.com>
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
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
 * Common TLS type definitions shared between manager and cache process
 */

#ifdef COMMON_VTLS_TYPES_H_INCLUDED
#  error "common_vtls_types.h included multiple times"
#endif
#define COMMON_VTLS_TYPES_H_INCLUDED

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "vqueue.h"

/* TLS Protocol versions */
typedef enum {
#define VTLS_PROTO(vp, n, sp, s) vp = n,
#include "common/common_tls_protos.h"
#undef VTLS_PROTO
} VTLS_PROTOCOL;

#define VTLS_PROTO_DEFAULT (TLSv1_2_PROTO | TLSv1_3_PROTO)

/* TLS configuration options - used for both global and per-frontend config */
struct vtls_cfg_opts {
	char			*ciphers;
	char			*ciphersuites;
	int			protos;
	int			prefer_server_ciphers;
	int			sni_nomatch_abort;
	char			*ecdh_curve;
};

/* Forward declarations */
struct vtls_ctx;
struct vtls_sni_map;

/* Per-endpoint TLS configuration */
struct vtls {
	unsigned			magic;
#define VTLS_MAGIC			0xf58b6112
	VTAILQ_HEAD(, vtls_ctx)		ctxs;
	struct vtls_ctx			*d_ctx;
	struct vtls_ctx			*d_ctx_scratch;
	struct vtls_sni_map		*sni;
	struct vtls_sni_map		*sni_scratch;
	struct vtls_cfg_opts		cfg[1];
	int				sni_match_global;
	int				protos;
};
