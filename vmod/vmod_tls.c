/*-
 * Copyright (c) 2020 Varnish Software AS
 * All rights reserved.
 *
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
 * TLS inspection VMOD
 */

#include "config.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include "cache/cache.h"
#include "vcl.h"
#include "vcc_tls_if.h"

/*
 * External functions from cache_client_ssl.c
 */
const SSL *VTLS_tls_ctx(const struct vrt_ctx *ctx);
const char *VTLS_ja3(const struct vrt_ctx *ctx);
const char *VTLS_ja4(const struct vrt_ctx *ctx);
const char *VTLS_ja4_r(const struct vrt_ctx *ctx);
const char *VTLS_ja4_o(const struct vrt_ctx *ctx);
const char *VTLS_ja4_ro(const struct vrt_ctx *ctx);

/*
 * For the backend-side, this VMOD is only callable when we have an
 * established backend connection, i.e. vcl_backend_response.
 */
#define BERESP_CHECK(r)						\
	if (ctx->bo != NULL					\
	    && ctx->method != VCL_MET_BACKEND_RESPONSE		\
	    && ctx->method != VCL_MET_PIPE) {			\
		VRT_fail(ctx, "Error: vmod-tls in a backend "	\
		    "transaction is only callable from "	\
		    "vcl_backend_response");			\
		return (r);					\
	}

#define BERESP_CHECK_RET_0 BERESP_CHECK(0)
#define BERESP_CHECK_RET_NULL BERESP_CHECK(NULL)

#define VMOD_TLS_CLIENT_STRING(name)					\
	VCL_STRING								\
	vmod_ ## name(VRT_CTX)							\
	{									\
		AN(ctx->method & VCL_MET_TASK_C);				\
		const char *_p = VTLS_ ## name(ctx);				\
		if (_p == NULL)							\
			return (NULL);						\
		return (WS_Copy(ctx->ws, _p, -1));				\
	}

VMOD_TLS_CLIENT_STRING(ja3)
VMOD_TLS_CLIENT_STRING(ja4)
VMOD_TLS_CLIENT_STRING(ja4_r)
VMOD_TLS_CLIENT_STRING(ja4_o)
VMOD_TLS_CLIENT_STRING(ja4_ro)

VCL_BOOL
vmod_is_tls(VRT_CTX)
{
	BERESP_CHECK_RET_0;
	return (VTLS_tls_ctx(ctx) != NULL);
}

VCL_STRING
vmod_version(VRT_CTX)
{
	const SSL *ssl;

	BERESP_CHECK_RET_NULL;
	ssl = VTLS_tls_ctx(ctx);
	if (ssl)
		return (SSL_get_version(ssl));
	return (NULL);
}

VCL_STRING
vmod_cipher(VRT_CTX)
{
	const SSL *ssl;

	BERESP_CHECK_RET_NULL;
	ssl = VTLS_tls_ctx(ctx);
	if (ssl)
		return (SSL_get_cipher_name(ssl));
	return (NULL);
}

VCL_STRING
vmod_authority(VRT_CTX)
{
	const SSL *ssl;

	BERESP_CHECK_RET_NULL;
	ssl = VTLS_tls_ctx(ctx);
	if (ssl)
		return (SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name));
	return (NULL);
}

VCL_STRING
vmod_alpn(VRT_CTX)
{
	const SSL *ssl;
	unsigned l = 0;
	char *p = NULL, *q;

	BERESP_CHECK_RET_NULL;
	ssl = VTLS_tls_ctx(ctx);
	if (!ssl)
		return (NULL);

	SSL_get0_alpn_selected(ssl, TRUST_ME(&p), &l);
	if (p && l > 0) {
		q = WS_Alloc(ctx->ws, l + 1);
		if (!q) {
			VRT_fail(ctx, "vmod_tls: Out of workspace");
			return (NULL);
		}
		memcpy(q, p, l);
		q[l] = 0;
		return (q);
	}

	return (NULL);
}

VCL_STRING
vmod_cert_sign(VRT_CTX)
{
	X509 *cert, *xref;
	const SSL *ssl;
	int nid;

	xref = NULL;
	BERESP_CHECK_RET_NULL;
	ssl = VTLS_tls_ctx(ctx);
	if (!ssl)
		return (NULL);
	if (ctx->req != NULL) {
		CHECK_OBJ(ctx->req, REQ_MAGIC);
		cert = SSL_get_certificate(ssl);
	} else {
		CHECK_OBJ_NOTNULL(ctx->bo, BUSYOBJ_MAGIC);
		cert = SSL_get_peer_certificate(ssl);
		xref = cert;
	}
	if (!cert)
		return (NULL);
	nid = X509_get_signature_nid(cert);
	X509_free(xref);
	return (OBJ_nid2sn(nid));
}

VCL_STRING
vmod_cert_key(VRT_CTX)
{
	X509 *cert, *xref;
	EVP_PKEY *key;
	const SSL *ssl;
	const char *cert_algo;
	const char *p = NULL;

	xref = NULL;
	BERESP_CHECK_RET_NULL;
	ssl = VTLS_tls_ctx(ctx);
	if (!ssl)
		return (NULL);

	if (ctx->req != NULL) {
		CHECK_OBJ(ctx->req, REQ_MAGIC);
		cert = SSL_get_certificate(ssl);
	} else {
		CHECK_OBJ_NOTNULL(ctx->bo, BUSYOBJ_MAGIC);
		cert = SSL_get_peer_certificate(ssl);
		xref = cert;
	}
	if (!cert)
		return (NULL);
	key = X509_get_pubkey(cert);
	if (!key) {
		X509_free(xref);
		return (NULL);
	}
	switch (EVP_PKEY_id(key)) {
#define CERT_ALGO(evpk, str)			\
		case evpk:			\
			cert_algo = (str);	\
			break;
		CERT_ALGO(EVP_PKEY_NONE, "none")
		CERT_ALGO(EVP_PKEY_RSA, "RSA")
		CERT_ALGO(EVP_PKEY_DSA, "DSA")
		CERT_ALGO(EVP_PKEY_EC, "EC")
	default:
		cert_algo = "n/a";
	}

	p = WS_Printf(ctx->ws, "%s%d", cert_algo, EVP_PKEY_bits(key));
	if (!p)
		VRT_fail(ctx, "vmod_tls: Out of workspace");
	EVP_PKEY_free(key);
	X509_free(xref);
	return (p);
}
