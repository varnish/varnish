/*-
 * Copyright (c) 2015 Varnish Software AS
 * All rights reserved.
 *
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
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
 * Backend SSL/TLS connection handling
 */

#include "config.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "cache/cache_vinyld.h"
#include "cache/cache_conn_pool_ssl.h"
#include "cache/cache_pool.h"
#include "cache_tls.h"

#include "vtcp.h"
#include "vtim.h"

struct bssl_ctx {
	unsigned		magic;
#define BSSL_CTX_MAGIC		0x1bd8dc29

	SSL_CTX			*ctx;
};

static struct bssl_ctx	*bssl_ctx;

void
BSSL_Init(void)
{

	ASSERT_CLI();
	AZ(bssl_ctx);

	ALLOC_OBJ(bssl_ctx, BSSL_CTX_MAGIC);
	AN(bssl_ctx);
	bssl_ctx->ctx = SSL_CTX_new(TLS_client_method());
	AN(bssl_ctx->ctx);
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
	/*
	 * Many backends close TCP without TLS close_notify.
	 * Treat unexpected EOF as clean shutdown (OpenSSL 3.0+).
	 */
	(void)SSL_CTX_set_options(bssl_ctx->ctx, SSL_OP_IGNORE_UNEXPECTED_EOF);
#endif
	AN(SSL_CTX_set_default_verify_paths(bssl_ctx->ctx));
	(void)SSL_CTX_set_verify(bssl_ctx->ctx, SSL_VERIFY_PEER, NULL);
}

static void
bssl_vtp_free(struct vtls_sess **p_tsp)
{
	struct vtls_sess *tsp;

	TAKE_OBJ_NOTNULL(tsp, p_tsp, VTLS_SESS_MAGIC);
	AZ(tsp->buf);
	if (tsp->ssl)
		SSL_free(tsp->ssl);
	FREE_OBJ(tsp);
}

/*--------------------------------------------------------------------*/

static int
bssl_vfy_cb(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	int err;
	SSL *ssl;
	struct vtls_sess *tsp;

	err = X509_STORE_CTX_get_error(x509_ctx);
	if (err != X509_V_OK) {
		ssl = X509_STORE_CTX_get_ex_data(x509_ctx,
		    SSL_get_ex_data_X509_STORE_CTX_idx());
		AN(ssl);
		CAST_OBJ_NOTNULL(tsp, SSL_get_ex_data(ssl, 0), VTLS_SESS_MAGIC);
		VTLS_LOG(tsp->log, SLT_BackendSSL,
		    "Server verification failed: %s",
		    X509_verify_cert_error_string(err));
	}

	return (preverify_ok);
}

/*--------------------------------------------------------------------*/

struct vtls_sess *
bssl_vtp_init(int fd, double tmo, struct vsl_log *vsl,
    unsigned ssl_flags, const char *ssl_sniname)
{
	struct vtls_sess *tsp;
	X509_VERIFY_PARAM *vpm;
	int i;

	CHECK_OBJ_NOTNULL(bssl_ctx, BSSL_CTX_MAGIC);
	AN(bssl_ctx->ctx);

	assert(fd >= 0);
	AN(ssl_flags & BSSL_F_ENABLE);
	AZ(isnan(tmo));

	ALLOC_OBJ(tsp, VTLS_SESS_MAGIC);
	if (tsp == NULL)
		return (NULL);
	tsp->log->vsl = vsl;

	(void)VTCP_nonblocking(fd);

	tsp->ssl = SSL_new(bssl_ctx->ctx);
	if (tsp->ssl == NULL) {
		VTLS_vsl_ssllog(tsp->log);
		bssl_vtp_free(&tsp);
		return (NULL);
	}

	AN(SSL_set_ex_data(tsp->ssl, 0, tsp));

	AN(ssl_sniname);
	if (!(ssl_flags & BSSL_F_NOSNI)) {
		i = SSL_set_tlsext_host_name(tsp->ssl, TRUST_ME(ssl_sniname));
		if (!i) {
			VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
			bssl_vtp_free(&tsp);
			return (NULL);
		}
	}

	if (ssl_flags & BSSL_F_NOVERIFY)
		SSL_set_verify(tsp->ssl, SSL_VERIFY_NONE, NULL);
	else
		SSL_set_verify(tsp->ssl, SSL_VERIFY_PEER, bssl_vfy_cb);

	vpm = SSL_get0_param(tsp->ssl);
	AN(vpm);
	AN(X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_TRUSTED_FIRST));

	if (ssl_flags & BSSL_F_VERIFY_HOST) {
		AN(X509_VERIFY_PARAM_set1_host(vpm, ssl_sniname, 0));
		X509_VERIFY_PARAM_set_hostflags(vpm,
		    X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT);
	}

	AN(SSL_set_fd(tsp->ssl, fd));
	SSL_set_connect_state(tsp->ssl);

	if (VTLS_do_handshake(tsp, fd, tmo)) {
		bssl_vtp_free(&tsp);
		return (NULL);
	}

	(void)VTCP_blocking(fd);

	VTLS_vsl_ssllog(tsp->log);
	tsp->log->vsl = NULL;
	return (tsp);
}

void
bssl_vtp_fini(struct vtls_sess **ptsp)
{
	struct vtls_sess *tsp;

	TAKE_OBJ_NOTNULL(tsp, ptsp, VTLS_SESS_MAGIC);
	AZ(tsp->log->vsl);
	bssl_vtp_free(&tsp);
	AZ(tsp);
	VTLS_flush_errors();
}

void
bssl_vtp_begin(struct pool *pp, struct vtls_sess *tsp, struct vsl_log *vsl)
{
	CHECK_OBJ_NOTNULL(bssl_ctx, BSSL_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);
	CHECK_OBJ_NOTNULL(tsp, VTLS_SESS_MAGIC);
	AZ(tsp->buf);
	tsp->buf = VTLS_buf_alloc(pp->mpl_ssl);
	AN(tsp->buf);
	AZ(tsp->log->vsl);
	tsp->log->vsl = vsl;
}

void
bssl_vtp_end(struct vtls_sess *tsp)
{
	CHECK_OBJ_NOTNULL(bssl_ctx, BSSL_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(tsp, VTLS_SESS_MAGIC);
	AN(tsp->buf);
	VTLS_buf_free(&tsp->buf);
	AZ(tsp->buf);
	tsp->log->vsl = NULL;
}
