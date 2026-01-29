/*-
 * Copyright (c) 2019, 2023 Varnish Software AS
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
 * Client-side TLS termination
 */

#include "config.h"

#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdlib.h>

#include "common/common_vtls_types.h"
#include "cache/cache_varnishd.h"
#include "cache/cache_conn_oper.h"
#include "cache/cache_pool.h"
#include "vcli_serve.h"
#include "cache_tls.h"
#include "cache/cache_transport.h"
#include "common/heritage.h"

#include "vend.h"
#include "vqueue.h"
#include "vsb.h"
#include "vtcp.h"
#include "vtim.h"
#include "vtree.h"

#include "cache_client_ssl.h"

VTAILQ_HEAD(v_ctx_list, vtls_ctx);

struct vtls_sni_map;
VRBT_HEAD(vtls_sni_rbtree, vtls_sni_key);
VRBT_PROTOTYPE(vtls_sni_rbtree, vtls_sni_key, tree, vtls_sni_key_cmp);

static int vtls_sni_key_cmp(const struct vtls_sni_key *a,
    const struct vtls_sni_key *b);

struct vtls_sni_map {
	unsigned			magic;
#define VTLS_SNI_MAP_MAGIC		0x15335fe1
	struct vtls_sni_rbtree		root;
	VTAILQ_ENTRY(vtls_sni_map)	list;
};

VRBT_GENERATE(vtls_sni_rbtree, vtls_sni_key, tree, vtls_sni_key_cmp);

struct vtls_options {
	int protos;
	int prefer_server_ciphers;
	int is_default;
	char *cert_key;
	char *key;
	char *dh;
	const char *id;
	const char *fe;
	const char *ciphers;
	const char *ciphersuites;
	const char *sni_list;
};

void
VTLS_del_sess(struct pool *pp, struct vtls_sess **ptsp)
{
	struct vtls_sess *tsp;

	CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);
	TAKE_OBJ_NOTNULL(tsp, ptsp, VTLS_SESS_MAGIC);

	free(tsp->ja3);

	if (tsp->buf != NULL)
		VTLS_buf_free(&tsp->buf);
	if (tsp->ssl)
		SSL_free(tsp->ssl);
	FREE_OBJ(tsp);
}

void
VTLS_vsl_set(struct vtls_sess *tsp, struct vsl_log *vsl)
{
	CHECK_OBJ_ORNULL(tsp, VTLS_SESS_MAGIC);
	if (tsp == NULL)
		return;

	tsp->log->vsl = vsl;
}

static int
vtls_sni_key_cmp(const struct vtls_sni_key *a,
    const struct vtls_sni_key *b)
{
	AN(a->id);
	AN(b->id);
	return (strcasecmp(a->id, b->id));
}

static struct vtls_sni_map *
vtls_sni_map_new(void)
{
	struct vtls_sni_map *m;

	ALLOC_OBJ(m, VTLS_SNI_MAP_MAGIC);
	AN(m);
	VRBT_INIT(&m->root);
	return (m);
}

static void
vtls_sni_key_free(struct vtls_sni_key *k)
{
	CHECK_OBJ_ORNULL(k, VTLS_SNI_KEY_MAGIC);
	if (k) {
		free(k->id);
		FREE_OBJ(k);
	}
}

static struct vtls_sni_key *
vtls_sni_key_alloc(const char *id, unsigned is_wildcard, struct vtls_ctx *ctx)
{
	struct vtls_sni_key *k;

	ALLOC_OBJ(k, VTLS_SNI_KEY_MAGIC);
	AN(k);

	REPLACE(k->id, id);
	k->is_wildcard = is_wildcard;
	k->ctx = ctx;
	VTAILQ_INIT(&k->dups);

	return (k);
}

static int
vtls_sni_map_add(struct vtls_sni_map *m, char *id,
    struct vtls_ctx *ctx)
{
	struct vtls_sni_key *k, *r;
	unsigned is_wildcard = 0;

	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
	AN(id);

	if (strstr(id, "*.") == id) {
		is_wildcard = 1;
		id++;
	}
	k = vtls_sni_key_alloc(id, is_wildcard, ctx);

	r = VRBT_INSERT(vtls_sni_rbtree, &m->root, k);
	if (r) {
		/* duplicate: New cert takes precedence */
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		VRBT_REMOVE(vtls_sni_rbtree, &m->root, r);
		VTAILQ_CONCAT(&k->dups, &r->dups, dups_list);
		VTAILQ_INSERT_HEAD(&k->dups, r, dups_list);
		AZ(VRBT_INSERT(vtls_sni_rbtree, &m->root, k));
	}

	return (0);
}

static struct vtls_ctx *
_vtls_sni_lookup(const struct vtls_sni_map *m, const char *id, int wc)
{
	struct vtls_sni_key k, *r;

	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
	INIT_OBJ(&k, VTLS_SNI_KEY_MAGIC);
	k.id = TRUST_ME(id);

	r = VRBT_FIND(vtls_sni_rbtree, &m->root, &k);
	if (r) {
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		return (r->ctx);
	} else if (!wc)
		return (NULL);

	/* Do another lookup for wildcard matches */
	k.id = strchr(id, '.');
	if (k.id == NULL)
		return (NULL);
	r = VRBT_FIND(vtls_sni_rbtree, &m->root, &k);
	if (r) {
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		if (!r->is_wildcard)
			return (NULL);
		return (r->ctx);
	}

	return (NULL);
}

static struct vtls_ctx *
vtls_sni_lookup(const struct vtls_sni_map *m, const char *id)
{
	return (_vtls_sni_lookup(m, id, 1));
}

static void
vtls_ctx_free(struct vtls_ctx *c)
{
	CHECK_OBJ_ORNULL(c, VTLS_CTX_MAGIC);
	if (c == NULL)
		return;

	SSL_CTX_free(c->ctx);
	free(c->name_id);
	FREE_OBJ(c);
}

static int
vtls_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
	int r;
	const unsigned char *p;
	unsigned plen;
	static const unsigned char protos_h2[] = {
		2, 'h', '2',
		8, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};

	static const unsigned char protos_h11[] = {
		8, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};

	(void)arg;
	(void)ssl;

	if (FEATURE(FEATURE_HTTP2)) {
		p = protos_h2;
		plen = sizeof(protos_h2);
	} else {
		p = protos_h11;
		plen = sizeof(protos_h11);
	}

	r = SSL_select_next_proto(TRUST_ME(out), outlen, p, plen, in, inlen);
	if (r != OPENSSL_NPN_NEGOTIATED) {
		return (SSL_TLSEXT_ERR_NOACK);
	}

	return (SSL_TLSEXT_ERR_OK);
}

static void
vtls_set_protos(SSL *ssl, int protos)
{
	int proto_min, proto_max;

	AN(ssl);
	proto_min = proto_max = 0;
	if (protos == 0)
		protos = VTLS_PROTO_DEFAULT;

#define VTLS_PROTO(vtls_proto, n, ssl_proto, s) \
	if (protos & vtls_proto) {              \
		if (!proto_min)                 \
			proto_min = ssl_proto;  \
		proto_max = ssl_proto;          \
	}
#include "common/common_tls_protos.h"

	SSL_set_min_proto_version(ssl, proto_min);
	SSL_set_max_proto_version(ssl, proto_max);
}

static int
vtls_sni(const struct vtls *tls, SSL *ssl, const char *sn, int protos)
{
	struct vtls_ctx *tls_ctx = NULL;
	int result = SSL_TLSEXT_ERR_NOACK;

	CHECK_OBJ_NOTNULL(tls, VTLS_MAGIC);
	CHECK_OBJ_ORNULL(tls->sni, VTLS_SNI_MAP_MAGIC);
	CHECK_OBJ_ORNULL(heritage.tls->sni, VTLS_SNI_MAP_MAGIC);
	AN(sn);
	AN(ssl);

	if (tls->cfg->sni_nomatch_abort)
		result = SSL_TLSEXT_ERR_ALERT_FATAL;

	/* Check local list */
	if (tls->sni)
		tls_ctx = vtls_sni_lookup(tls->sni, sn);

	/* Check global certs */
	if (tls_ctx == NULL && heritage.tls->sni != NULL &&
	    tls != heritage.tls && tls->sni_match_global)
		tls_ctx = vtls_sni_lookup(heritage.tls->sni, sn);

	if (tls_ctx != NULL) {
		CHECK_OBJ_NOTNULL(tls_ctx, VTLS_CTX_MAGIC);
		if (0 != tls_ctx->protos)
			protos = tls_ctx->protos;
		SSL_set_SSL_CTX(ssl, tls_ctx->ctx);
		result = SSL_TLSEXT_ERR_OK;
	}

	vtls_set_protos(ssl, protos);

	return (result);
}

/* Parses a server name extension payload.
   The format here is defined in RFC3546, section 3.1
 */
static int
vtls_server_name_parse(const unsigned char *p, ssize_t l, struct vsb *vsb)
{
	uint16_t ll, nl;

	/* first two bytes: length of list: */
	if (l <= 2)
		return (1);
	ll = vbe16dec(p);
	p += 2;
	l -= 2;

	/* Malformed server name list */
	if (ll != l || ll == 0)
		return (1);

	/* Only the host_name name type is specified, and no clients
	 * ever send more than one so we only consider the first list
	 * entry. */

	if (*p != TLSEXT_NAMETYPE_host_name)
		return (1);
	p++;
	l--;
	/* next two bytes: length of name entry */
	if (l <= 2)
		return (1);
	nl = vbe16dec(p);
	p += 2;
	l -= 2;
	if (nl > l)
		return (1);

	/* We make a copy to ensure we get something with a
	 * null byte at the end. */
	VSB_bcat(vsb, p, nl);
	return (0);
}

#define IS_GREASE_TLS(x) \
	((((x) & 0x0f0f) == 0x0a0a) && (((x) & 0xff) == (((x) >> 8) & 0xff)))

static void
vtls_ja3_parsefields(int s, const unsigned char *data, int len,
    struct vsb *ja3)
{
	int cnt;
	uint16_t tmp;
	int first = 1;

	for (cnt = 0; cnt < len; cnt += s) {
		if (s == 1)
			tmp = *data;
		else
			tmp = vbe16dec(data);

		data += s;

		if (s != 2 || !IS_GREASE_TLS(tmp)) {
			if (!first)
				VSB_putc(ja3, '-');

			first = 0;
			VSB_printf(ja3, "%i", tmp);
		}
	}
}

static int
vtls_get_ja3(SSL *ssl, struct sess *sp, struct vtls_sess *tsp)
{
	struct vsb ja3[1];
	size_t len, i;
	const unsigned char *p;
	int first, type, *out;
	char *ja3p;
	uintptr_t sn;

	sn = WS_Snapshot(sp->ws);
	WS_VSB_new(ja3, sp->ws);
	VSB_printf(ja3, "%i,", SSL_version(ssl));

	len = SSL_client_hello_get0_ciphers(ssl, &p);
	vtls_ja3_parsefields(2, p, len, ja3);
	VSB_putc(ja3, ',');

	if (SSL_client_hello_get1_extensions_present(ssl, &out, &len) == 1) {
		first = 1;
		for (i = 0; i < len; i++) {
			type = out[i];
			if (!IS_GREASE_TLS(type)) {
				if (!first)
					VSB_putc(ja3, '-');

				first = 0;
				VSB_printf(ja3, "%i", type);
			}
		}
		OPENSSL_free(out);
	}
	VSB_putc(ja3, ',');

	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_elliptic_curves, &p,
	    &len) == 1) {
		p += 2;
		len -= 2;
		vtls_ja3_parsefields(2, p, len, ja3);
	}
	VSB_putc(ja3, ',');

	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ec_point_formats, &p,
	    &len) == 1) {
		++p;
		--len;
		vtls_ja3_parsefields(1, p, len, ja3);
	}

	ja3p = WS_VSB_finish(ja3, sp->ws, NULL);
	if (ja3p == NULL) {
		VTLS_LOG(tsp->log, SLT_Error,
		    "Out of workspace_session during JA3 handling");
		return (1);
	}

	REPLACE(tsp->ja3, ja3p);
	WS_Reset(sp->ws, sn);
	return (0);
}

static int
vtls_clienthello_cb(SSL *ssl, int *al, void *priv)
{
	const struct vtls *tls;
	struct vtls_sess *tsp;
	struct sess *sp;
	size_t l;
	const unsigned char *ext;
	struct vsb vsb[1];
	char *sn;
	int err, protos;

	AN(ssl);
	CAST_OBJ_NOTNULL(sp, SSL_get_app_data(ssl), SESS_MAGIC);
	CAST_OBJ_NOTNULL(tsp, sp->tls, VTLS_SESS_MAGIC);
	CAST_OBJ_NOTNULL(tls, tsp->priv_local, VTLS_MAGIC);

	(void)al;
	(void)priv;

	protos = tls->protos;
	if (protos == 0)
		protos = heritage.tls->protos;

	if (cache_param->tls_ja3 && vtls_get_ja3(ssl, sp, tsp) != 0)
		return (SSL_CLIENT_HELLO_ERROR);

	if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name,
	    &ext, &l)) {
		tsp->sni_result = SSL_TLSEXT_ERR_NOACK;
		vtls_set_protos(ssl, protos);
		return (SSL_CLIENT_HELLO_SUCCESS);
	}

	WS_VSB_new(vsb, sp->ws);
	err = vtls_server_name_parse(ext, l, vsb);
	sn = WS_VSB_finish(vsb, sp->ws, NULL);
	if (err)
		return (SSL_CLIENT_HELLO_ERROR);
	if (sn == NULL) {
		VTLS_LOG(tsp->log, SLT_Error,
		    "Out of workspace_session during SNI handling");
		return (SSL_CLIENT_HELLO_ERROR);
	}
	tsp->sni_result = vtls_sni(tls, ssl, sn, protos);

	return (SSL_CLIENT_HELLO_SUCCESS);
}

static int
vtls_sni_cb(SSL *ssl, int *al, void *priv)
{
	struct vtls_sess *tsp;
	struct sess *sp;
	/*
	 * Even though we do the important bits in the ClientHello
	 * callback, this callback is still needed in order to
	 * acknowledge the servername request.
	 */

	(void)al;
	(void)priv;
	CAST_OBJ_NOTNULL(sp, SSL_get_app_data(ssl), SESS_MAGIC);
	CAST_OBJ_NOTNULL(tsp, sp->tls, VTLS_SESS_MAGIC);

	return (tsp->sni_result);
}

static void
vtls_sess_abandon(struct worker *wrk, struct req *req,
    struct sess *sp, stream_close_t reason)
{
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	Req_Cleanup(sp, wrk, req);
	Req_Release(req);
	SES_Delete(sp, reason, NAN);
}

static void v_matchproto_(task_func_t)
vtls_new_session(struct worker *wrk, void *arg)
{
	struct req *req;
	struct sess *sp;
	struct vtls *vtls_local;
	struct vtls_ctx *tls_ctx;
	struct vtls_sess *tsp;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(wrk->pool, POOL_MAGIC);
	CAST_OBJ_NOTNULL(req, arg, REQ_MAGIC);
	sp = req->sp;
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->listen_sock, LISTEN_SOCK_MAGIC);
	CHECK_OBJ_NOTNULL(sp->listen_sock->tls, VTLS_MAGIC);
	vtls_local = sp->listen_sock->tls;

	CHECK_OBJ_NOTNULL(heritage.tls, VTLS_MAGIC);

	ALLOC_OBJ(tsp, VTLS_SESS_MAGIC);
	AN(tsp);
	tsp->log->is_client = 1;
	tsp->log->vxid = sp->vxid;
	sp->tls = tsp;
	tsp->priv_local = vtls_local;

	if (vtls_local->d_ctx)
		tls_ctx = vtls_local->d_ctx;
	else if (heritage.tls->d_ctx)
		tls_ctx = heritage.tls->d_ctx;
	else {
		VTLS_LOG(tsp->log, SLT_TLS, "No certificates loaded");
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_BAD);
		return;
	}

	CHECK_OBJ_NOTNULL(tls_ctx, VTLS_CTX_MAGIC);

	tsp->ssl = SSL_new(tls_ctx->ctx);
	if (tsp->ssl == NULL) {
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_OVERFLOW);
		return;
	}

	if (SSL_set_app_data(tsp->ssl, sp) == 0) {
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_OVERFLOW);
		return;
	}

	VTCP_nonblocking(sp->fd);
	if (SSL_set_fd(tsp->ssl, sp->fd) == 0) {
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_OVERFLOW);
		return;
	}

	SSL_set_accept_state(tsp->ssl);
	if (VTLS_do_handshake(tsp, sp->fd,
	    cache_param->tls_handshake_timeout)) {
		vtls_sess_abandon(wrk, req, sp, SC_RX_BAD);
		return;
	}

	sp->t_idle = VTIM_real();
	req->htc->oper = VTLS_conn_oper_client(tsp, &req->htc->oper_priv);
	(void)VTCP_blocking(sp->fd);
	SES_SetTransport(wrk, sp, req, &HTTP1_transport);
}

struct transport TLS_transport = {
	.name =			"TLS",
	.proto_ident =		"TLS",
	.magic =		TRANSPORT_MAGIC,
	.new_session =		vtls_new_session
};

/* Client-side TLS VCO */
static ssize_t v_matchproto_(vco_read_f)
vtls_read_client(void *priv, int fd, void *buf, size_t len)
{
	struct vtls_sess *tsp;
	int i, e;

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	AN(tsp->ssl);
	assert(fd == SSL_get_fd(tsp->ssl));

	if (len > INT_MAX)
		len = INT_MAX;
	i = SSL_read(tsp->ssl, buf, len);
	e = SSL_get_error(tsp->ssl, i);
	if (i <= 0 && e != SSL_ERROR_ZERO_RETURN)
		VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
	VTLS_vsl_ssllog(tsp->log);
	return (i);
}

static ssize_t v_matchproto_(vco_write_f)
vtls_write_client(void *priv, int fd, const void *buf, size_t len)
{
	struct vtls_sess *tsp;
	int i;

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	AN(tsp->ssl);
	assert(fd == SSL_get_fd(tsp->ssl));

	if (len > INT_MAX)
		len = INT_MAX;
	i = SSL_write(tsp->ssl, buf, len);
	if (i <= 0)
		VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
	VTLS_vsl_ssllog(tsp->log);
	return (i);
}

static ssize_t v_matchproto_(vco_writev_f)
vtls_writev_client(void *priv, int fd, const struct iovec *iov, int iovcnt)
{
	struct vtls_sess *tsp;
	int i;

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	AN(tsp->ssl);
	assert(fd == SSL_get_fd(tsp->ssl));

	if (iovcnt == 0)
		return (0);

	AN(iov);
	i = iov[0].iov_len;
	if (i > INT_MAX)
		i = INT_MAX;
	i = SSL_write(tsp->ssl, iov[0].iov_base, i);
	if (i <= 0)
		VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
	VTLS_vsl_ssllog(tsp->log);
	return (i);
}

static int v_matchproto_(vco_check_f)
vtls_check_client(ssize_t a)
{
	(void)a;
	return (1);
}

static const struct vco vtls_oper_client = {
	.read = vtls_read_client,
	.write = vtls_write_client,
	.writev_prep = NULL,
	.writev = vtls_writev_client,
	.nb_read = NULL,
	.nb_writev = NULL,
	.check = vtls_check_client,
};

const struct vco *
VTLS_conn_oper_client(struct vtls_sess *tsp, void **ppriv)
{
	CHECK_OBJ_NOTNULL(tsp, VTLS_SESS_MAGIC);
	AN(ppriv);
	*ppriv = tsp;
	return (&vtls_oper_client);
}

/* Buffer management */
struct vtls_buf *
VTLS_buf_alloc(struct mempool *mpl_ssl)
{
	struct vtls_buf *buf;
	unsigned buflen = 16384;

	buf = MPL_Get(mpl_ssl, NULL);
	if (buf == NULL)
		return (NULL);

	INIT_OBJ(buf, VTLS_BUF_MAGIC);
	buf->buflen = buflen;
	buf->pool = mpl_ssl;
	return (buf);
}

void
VTLS_buf_free(struct vtls_buf **pbuf)
{
	struct vtls_buf *buf;

	AN(pbuf);
	TAKE_OBJ_NOTNULL(buf, pbuf, VTLS_BUF_MAGIC);
	MPL_Free(buf->pool, buf);
}

/*
 * Base64 decode PEM data received from manager
 */
static char *
vtls_cli_base64_decode(const char *b64, int *out_len)
{
	BIO *bio, *b64bio;
	int b64_len;
	char *buf;

	AN(b64);
	AN(out_len);

	b64_len = strlen(b64);
	buf = malloc(b64_len);  /* Decoded is always smaller */
	AN(buf);

	b64bio = BIO_new(BIO_f_base64());
	AN(b64bio);
	BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new_mem_buf(TRUST_ME(b64), b64_len);
	AN(bio);
	BIO_push(b64bio, bio);

	*out_len = BIO_read(b64bio, buf, b64_len);
	assert(*out_len >= 0);

	BIO_free_all(b64bio);
	return (buf);
}

/*
 * Password callback for PEM reading.
 * Returns 0 to indicate no password is available, which causes encrypted
 * PEM files to fail loading rather than prompting on stdin.
 */
static int
pass_cb(char *buf, int size, int rwflag, void *priv)
{
	(void)buf;
	(void)size;
	(void)rwflag;
	(void)priv;
	return (0);
}

/*
 * Create SSL_CTX from PEM data in memory.
 * If key/key_len is provided, use that for the private key.
 * Otherwise try to find the private key in the cert PEM.
 * If px509 is not NULL, the X509 certificate is returned (caller must free).
 */
static struct vtls_ctx *
vtls_ctx_new_from_pem(struct cli *cli, const char *name_id,
    const char *pem, int pem_len, const char *key, int key_len,
    int protos, int prefer_server_ciphers,
    const char *ciphers, const char *ciphersuites, X509 **px509)
{
	struct vtls_ctx *vc;
	BIO *src;
	X509 *x509, *t_ca;
	EVP_PKEY *pkey;
	unsigned long e;
	char errbuf[256];

	AN(pem);
	AN(pem_len);

	if (px509 != NULL)
		*px509 = NULL;

	ALLOC_OBJ(vc, VTLS_CTX_MAGIC);
	AN(vc);
	REPLACE(vc->name_id, name_id);
	vc->protos = protos;

	vc->ctx = SSL_CTX_new(TLS_server_method());
	if (vc->ctx == NULL) {
		VCLI_Out(cli, "Failed to create SSL_CTX\n");
		vtls_ctx_free(vc);
		return (NULL);
	}

	/* Set session id context */
	AN(SSL_CTX_set_session_id_context(vc->ctx,
	    (const unsigned char *)"varnishd", strlen("varnishd")));

	/* Set options */
	if (prefer_server_ciphers)
		(void)SSL_CTX_set_options(vc->ctx,
		    SSL_OP_CIPHER_SERVER_PREFERENCE);
	(void)SSL_CTX_set_options(vc->ctx, SSL_OP_NO_RENEGOTIATION);

	/* Enable ECDH */
	AN(SSL_CTX_set_ecdh_auto(vc->ctx, 1));

	/* Set ciphers if specified */
	if (ciphers != NULL && *ciphers != '\0') {
		if (SSL_CTX_set_cipher_list(vc->ctx, ciphers) != 1) {
			VCLI_Out(cli, "Invalid cipher list: %s\n", ciphers);
			vtls_ctx_free(vc);
			return (NULL);
		}
	}

	/* Set ciphersuites (TLSv1.3) if specified */
	if (ciphersuites != NULL && *ciphersuites != '\0') {
		if (SSL_CTX_set_ciphersuites(vc->ctx, ciphersuites) != 1) {
			VCLI_Out(cli, "Invalid ciphersuites: %s\n",
			    ciphersuites);
			vtls_ctx_free(vc);
			return (NULL);
		}
	}

	/* Load certificate from PEM data */
	src = BIO_new_mem_buf(TRUST_ME(pem), pem_len);
	if (src == NULL) {
		VCLI_Out(cli, "Failed to create BIO\n");
		vtls_ctx_free(vc);
		return (NULL);
	}

	x509 = PEM_read_bio_X509_AUX(src, NULL, pass_cb, NULL);
	if (x509 == NULL) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Error loading certificate: %s\n",
			    errbuf);
		}
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	if (SSL_CTX_use_certificate(vc->ctx, x509) != 1) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "SSL_CTX_use_certificate: %s\n", errbuf);
		}
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	/* Load certificate chain */
	SSL_CTX_clear_chain_certs(vc->ctx);
	while (1) {
		t_ca = PEM_read_bio_X509_AUX(src, NULL, pass_cb, NULL);
		if (t_ca == NULL) {
			e = ERR_peek_last_error();
			if (ERR_GET_LIB(e) == ERR_LIB_PEM &&
			    ERR_GET_REASON(e) == PEM_R_NO_START_LINE) {
				ERR_clear_error();
				break;
			}
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Error loading chain cert: %s\n", errbuf);
			X509_free(x509);
			BIO_free(src);
			vtls_ctx_free(vc);
			return (NULL);
		}

		if (SSL_CTX_add_extra_chain_cert(vc->ctx, t_ca) == 0) {
			ERR_error_string_n(ERR_get_error(), errbuf,
			    sizeof errbuf);
			VCLI_Out(cli, "Error adding chain cert: %s\n", errbuf);
			X509_free(t_ca);
			X509_free(x509);
			BIO_free(src);
			vtls_ctx_free(vc);
			return (NULL);
		}
	}

	/* Load private key - from separate data if provided, else from cert PEM */
	if (key != NULL && key_len > 0) {
		BIO *key_bio = BIO_new_mem_buf(TRUST_ME(key), key_len);
		if (key_bio == NULL) {
			VCLI_Out(cli, "Error creating key BIO\n");
			X509_free(x509);
			BIO_free(src);
			vtls_ctx_free(vc);
			return (NULL);
		}
		pkey = PEM_read_bio_PrivateKey(key_bio, NULL, pass_cb, NULL);
		BIO_free(key_bio);
	} else {
		BIO_reset(src);
		pkey = PEM_read_bio_PrivateKey(src, NULL, pass_cb, NULL);
	}
	if (pkey == NULL) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Error loading private key: %s\n",
			    errbuf);
		}
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	if (SSL_CTX_use_PrivateKey(vc->ctx, pkey) != 1) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "SSL_CTX_use_PrivateKey: %s\n", errbuf);
		}
		EVP_PKEY_free(pkey);
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	EVP_PKEY_free(pkey);
	BIO_free(src);

	/* Verify key matches certificate */
	if (SSL_CTX_check_private_key(vc->ctx) != 1) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Private key mismatch: %s\n", errbuf);
		}
		vtls_ctx_free(vc);
		return (NULL);
	}

	/* Set up callbacks */
	if (!SSL_CTX_set_tlsext_servername_callback(vc->ctx, vtls_sni_cb)) {
		VCLI_Out(cli, "Failed to set SNI callback\n");
		vtls_ctx_free(vc);
		return (NULL);
	}
	SSL_CTX_set_client_hello_cb(vc->ctx, vtls_clienthello_cb, NULL);
	SSL_CTX_set_alpn_select_cb(vc->ctx, vtls_alpn_select, NULL);

	if (px509 != NULL)
		*px509 = x509;
	else
		X509_free(x509);

	return (vc);
}

/*
 * CLI: vtls.cld_cert_load
 * Load certificate from manager (base64-encoded PEM data)
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_load(struct cli *cli, const char *const *av, void *priv)
{
	struct vtls *vtls = NULL;
	struct listen_sock *ls;
	struct vtls_ctx *vc;
	const char *id, *fe, *ciphers, *ciphersuites;
	const char *cert_b64, *privkey_b64;
	int protos, prefer_server_ciphers, is_default;
	char *cert, *privkey;
	int cert_len, privkey_len;
	X509 *x509 = NULL;

	(void)priv;

	/* Parse arguments:
	 * av[2] = id
	 * av[3] = frontend (empty string for global)
	 * av[4] = protos
	 * av[5] = prefer_server_ciphers
	 * av[6] = ciphers
	 * av[7] = ciphersuites
	 * av[8] = is_default
	 * av[9] = cert_b64 (base64-encoded certificate)
	 * av[10] = privkey_b64 (base64-encoded private key, or empty)
	 */
	AN(av[2]); AN(av[3]); AN(av[4]); AN(av[5]); AN(av[6]);
	AN(av[7]); AN(av[8]); AN(av[9]); AN(av[10]);

	id = av[2];
	fe = av[3];
	protos = atoi(av[4]);
	prefer_server_ciphers = atoi(av[5]);
	ciphers = av[6];
	ciphersuites = av[7];
	is_default = atoi(av[8]);
	cert_b64 = av[9];
	privkey_b64 = av[10];

	/* Find target vtls struct */
	if (*fe != '\0') {
		VTAILQ_FOREACH(ls, &heritage.socks, list) {
			CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
			if (ls->tls == NULL)
				continue;
			if (strcmp(ls->name, fe) == 0) {
				vtls = ls->tls;
				break;
			}
		}
		if (vtls == NULL) {
			VCLI_Out(cli, "Frontend '%s' not found\n", fe);
			VCLI_SetResult(cli, CLIS_CANT);
			return;
		}
	} else {
		vtls = heritage.tls;
	}

	if (vtls == NULL) {
		VCLI_Out(cli, "No TLS configuration available\n");
		VCLI_SetResult(cli, CLIS_CANT);
		return;
	}

	CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);

	/* Initialize scratch SNI map if not already done */
	if (vtls->sni_scratch == NULL)
		vtls->sni_scratch = vtls_sni_map_new();

	/* Decode certificate data */
	cert = vtls_cli_base64_decode(cert_b64, &cert_len);
	if (cert == NULL || cert_len == 0) {
		VCLI_Out(cli, "Failed to decode certificate data\n");
		VCLI_SetResult(cli, CLIS_CANT);
		free(cert);
		return;
	}

	/* Decode private key data if provided */
	privkey = NULL;
	privkey_len = 0;
	if (*privkey_b64 != '\0') {
		privkey = vtls_cli_base64_decode(privkey_b64, &privkey_len);
		if (privkey == NULL) {
			VCLI_Out(cli, "Failed to decode private key data\n");
			VCLI_SetResult(cli, CLIS_CANT);
			free(cert);
			return;
		}
	}

	/* Create SSL_CTX and get X509 for hostname extraction */
	vc = vtls_ctx_new_from_pem(cli, id, cert, cert_len, privkey, privkey_len,
	    protos, prefer_server_ciphers, ciphers, ciphersuites, &x509);

	/* Clear sensitive data from memory */
	ZERO_OBJ(cert, cert_len);
	free(cert);
	if (privkey != NULL) {
		ZERO_OBJ(privkey, privkey_len);
		free(privkey);
	}

	if (vc == NULL) {
		X509_free(x509);
		VCLI_SetResult(cli, CLIS_CANT);
		return;
	}

	X509_free(x509);

	/* Store in scratch for commit */
	if (is_default) {
		if (vtls->d_ctx_scratch != NULL)
			vtls_ctx_free(vtls->d_ctx_scratch);
		vtls->d_ctx_scratch = vc;
	} else {
		/* For non-default certs, add to SNI map (not implemented yet) */
		if (vtls->d_ctx_scratch != NULL)
			vtls_ctx_free(vtls->d_ctx_scratch);
		vtls->d_ctx_scratch = vc;
	}

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * CLI: vtls.cld_cert_commit
 * Commit staged certificates
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_commit(struct cli *cli, const char *const *av, void *priv)
{
	struct listen_sock *ls;
	struct vtls *vtls;

	(void)av;
	(void)priv;

	/* Commit global certificates */
	if (heritage.tls != NULL) {
		vtls = heritage.tls;
		CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);
		if (vtls->d_ctx_scratch != NULL) {
			if (vtls->d_ctx != NULL)
				vtls_ctx_free(vtls->d_ctx);
			vtls->d_ctx = vtls->d_ctx_scratch;
			vtls->d_ctx_scratch = NULL;
		}
	}

	/* Commit per-frontend certificates */
	VTAILQ_FOREACH(ls, &heritage.socks, list) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		if (ls->tls == NULL)
			continue;
		vtls = ls->tls;
		CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);
		if (vtls->d_ctx_scratch != NULL) {
			if (vtls->d_ctx != NULL)
				vtls_ctx_free(vtls->d_ctx);
			vtls->d_ctx = vtls->d_ctx_scratch;
			vtls->d_ctx_scratch = NULL;
		}
	}

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * CLI: vtls.cld_cert_discard
 * Discard staged certificates
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_discard(struct cli *cli, const char *const *av, void *priv)
{
	struct listen_sock *ls;
	struct vtls *vtls;

	(void)av;
	(void)priv;

	/* Discard global scratch */
	if (heritage.tls != NULL) {
		vtls = heritage.tls;
		CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);
		if (vtls->d_ctx_scratch != NULL) {
			vtls_ctx_free(vtls->d_ctx_scratch);
			vtls->d_ctx_scratch = NULL;
		}
	}

	/* Discard per-frontend scratch */
	VTAILQ_FOREACH(ls, &heritage.socks, list) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		if (ls->tls == NULL)
			continue;
		vtls = ls->tls;
		CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);
		if (vtls->d_ctx_scratch != NULL) {
			vtls_ctx_free(vtls->d_ctx_scratch);
			vtls->d_ctx_scratch = NULL;
		}
	}

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * CLI command table
 */
static struct cli_proto vtls_cli_cmds[] = {
	{ CLICMD_VTLS_CLD_CERT_LOAD, vtls_cli_cert_load, vtls_cli_cert_load },
	{ CLICMD_VTLS_CLD_CERT_COMMIT, vtls_cli_cert_commit,
	    vtls_cli_cert_commit },
	{ CLICMD_VTLS_CLD_CERT_DISCARD, vtls_cli_cert_discard,
	    vtls_cli_cert_discard },
	{ NULL }
};

/* Initialize certificate subsystem */
void
VTLS_tls_cert_init(void)
{
	/* Register CLI commands */
	CLI_AddFuncs(vtls_cli_cmds);
}

/* VMOD accessor: get SSL context */
const SSL *
VTLS_tls_ctx(const struct vrt_ctx *ctx)
{
	struct sess *sp;
	struct vtls_sess *tsp;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	if (ctx->req != NULL) {
		CHECK_OBJ(ctx->req, REQ_MAGIC);
		sp = ctx->req->sp;
		CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
		tsp = sp->tls;
		if (tsp == NULL)
			return (NULL);
		CHECK_OBJ(tsp, VTLS_SESS_MAGIC);
		return (tsp->ssl);
	}

	if (ctx->bo != NULL) {
		/* Backend connection TLS - not implemented in this port */
		return (NULL);
	}

	return (NULL);
}

/* VMOD accessor: get JA3 fingerprint */
const char *
VTLS_ja3(const struct vrt_ctx *ctx)
{
	struct sess *sp;
	struct vtls_sess *tsp;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	if (ctx->req == NULL)
		return (NULL);

	CHECK_OBJ(ctx->req, REQ_MAGIC);
	sp = ctx->req->sp;
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	tsp = sp->tls;
	if (tsp == NULL)
		return (NULL);
	CHECK_OBJ(tsp, VTLS_SESS_MAGIC);
	return (tsp->ja3);
}

/*
 * Suppress unused function warnings for SNI map functions that will be
 * used when multi-certificate SNI support is fully implemented.
 */
static void __attribute__((unused))
vtls_suppress_unused_warnings(void)
{
	(void)vtls_sni_map_new;
	(void)vtls_sni_key_free;
	(void)vtls_sni_map_add;
}
