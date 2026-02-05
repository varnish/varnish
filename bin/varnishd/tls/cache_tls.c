/*-
 * Copyright (c) 2015-2019 Varnish Software AS
 * All rights reserved.
 *
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
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
 * TLS VCO implementation using OpenSSL
 */

#include "config.h"

#include <errno.h>
#include <limits.h>
#include <math.h>
#include <poll.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "cache/cache_varnishd.h"
#include "cache/cache_conn_oper.h"
#include "cache/cache_conn_pool.h"
#include "cache/cache_pool.h"
#include "cache_tls.h"

#include "vtim.h"

/* Maximum TLS record payload size (16KB) */
#define TLS_MAX_RECLEN			(16 * 1024)

/* Initialize TLS buffer pool for a worker pool */
void
VTLS_NewPool(struct pool *pp, unsigned pool_no)
{
	char nb[12];

	CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);
	bprintf(nb, "ssl_buf%u", pool_no);
	pp->mpl_ssl = MPL_New(nb, &cache_param->sslbuf_pool,
	    &cache_param->ssl_buffer);
	AN(pp->mpl_ssl);
}

struct vtls_buf *
VTLS_buf_alloc(struct mempool *mpl_ssl)
{
	struct vtls_buf *buf;
	unsigned sz;

	buf = MPL_Get(mpl_ssl, &sz);
	if (buf == NULL)
		return (NULL);

	INIT_OBJ(buf, VTLS_BUF_MAGIC);
	buf->buflen = sz;
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

void
VTLS_buf_release(struct vtls_sess *tsp)
{
	/* Release our buf if we hold one. */

	CHECK_OBJ_NOTNULL(tsp, VTLS_SESS_MAGIC);
	if (tsp->buf == NULL)
		return;
	VTLS_buf_free(&tsp->buf);
	AZ(tsp->buf);
}

/* Flush OpenSSL's per thread ERR messages if any to free them. */
void
VTLS_flush_errors(void)
{
	while (ERR_get_error())
		;
}

/* Dump the per thread ERR messages present to log. */
void
VTLS_vsl_ssllog(struct vtls_log *log)
{
	unsigned long e;
	char buf[256];
	int tag;

	tag = log->is_client ? SLT_TLS : SLT_BackendSSL;

	while ((e = ERR_get_error())) {
		ERR_error_string_n(e, buf, sizeof buf);
		VTLS_LOG(log, tag, "%s", buf);
	}
}

void
VTLS_vsl_sslerr(struct vtls_log *log, SSL *ssl, int i)
{
	const char *l;
	int e;

	AN(ssl);
	e = SSL_get_error(ssl, i);

	switch (e) {
#define SSL_ERR(a) \
		case a: l = #a; break;
#include "tbl/ssl_err.h"
#undef SSL_ERR
		default:
			l = "<undefined>";
	}

	if (e == SSL_ERROR_SYSCALL && i < 0)
		VTLS_LOG(log, SLT_Error, "ssl:%d:%s:%s", i, l,
		    VAS_errtxt(errno));
	else
		VTLS_LOG(log, SLT_Error, "ssl:%d:%s", i, l);

	if (e != SSL_ERROR_SYSCALL)
		errno = EPROTO;

	VTLS_vsl_ssllog(log);
}

static ssize_t v_matchproto_(vco_read_f)
vtls_read_backend(void *priv, int fd, void *buf, size_t len)
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
vtls_write(void *priv, int fd, const void *buf, size_t len)
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
	errno = 0;
	i = SSL_read(tsp->ssl, buf, len);
	e = SSL_get_error(tsp->ssl, i);

	if (i < 0 && e == SSL_ERROR_WANT_READ)
		i = -2;
	else if (i < 0 && (e == SSL_ERROR_SYSCALL &&
	    (errno == EAGAIN || errno == EWOULDBLOCK)))
		i = -2;
	if (i <= 0 && (!(e == SSL_ERROR_SYSCALL && errno == 0)
	    && e != SSL_ERROR_ZERO_RETURN))
		VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);

	VTLS_vsl_ssllog(tsp->log);
	return (i);
}

static void v_matchproto_(vco_writev_prep_f)
vtls_writev_prep(void *priv, struct worker *wrk)
{
	/* Acquire a buf if we don't already hold one. */

	struct vtls_sess *tsp;

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);

	CHECK_OBJ_ORNULL(tsp->buf, VTLS_BUF_MAGIC);
	if (tsp->buf != NULL)
		return;

	CHECK_OBJ_NOTNULL(wrk->pool, POOL_MAGIC);
	tsp->buf = VTLS_buf_alloc(wrk->pool->mpl_ssl);
	AN(tsp->buf);
}

static ssize_t v_matchproto_(vco_writev_f)
vtls_writev(void *priv, int fd, const struct iovec *iov, int iovcnt)
{
	struct vtls_sess *tsp;
	ssize_t l, l2;
	unsigned buflen;
	int i;
	char *p;

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	AN(tsp->ssl);
	AN(tsp->log->vsl);
	CHECK_OBJ_NOTNULL(tsp->buf, VTLS_BUF_MAGIC);
	assert(fd == SSL_get_fd(tsp->ssl));

	if (iovcnt == 0)
		return (0);

	buflen = tsp->buf->buflen;
	if (buflen > TLS_MAX_RECLEN) {
		/* If we go above the maximum TLS record size (and since
		 * we don't enable SSL_MODE_ENABLE_PARTIAL_WRITE), OpenSSL
		 * will end up producing and sending a second half empty
		 * record. Limit the buffer size to avoid this. */
		buflen = TLS_MAX_RECLEN;
	}
	assert(buflen > 0);

	if (iovcnt == 1 || iov[0].iov_len + iov[1].iov_len > buflen) {
		/* Buffering would not help here */
		p = iov[0].iov_base;
		l = iov[0].iov_len;
	} else {
		p = tsp->buf->bytes;
		l = 0;
		for (i = 0; i < iovcnt && l < buflen; i++) {
			l2 = iov[i].iov_len;
			if (l + l2 > buflen)
				break;
			memcpy(p + l, iov[i].iov_base, l2);
			l += l2;
		}
	}

	if (l > INT_MAX)
		l = INT_MAX;
	i = SSL_write(tsp->ssl, p, l);
	if (i <= 0)
		VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
	VTLS_vsl_ssllog(tsp->log);
	return (i);
}

/*
 * TLS error checking is different from TCP - errors are reported via
 * SSL_get_error() and logged via VTLS_vsl_sslerr(), so we accept all
 * return values here.
 */
static int v_matchproto_(vco_check_f)
vtls_check(ssize_t a)
{
	(void)a;
	return (1);
}

/*
 * Wait for fd to become ready for the given events (POLLIN/POLLOUT),
 * with a timeout based on deadline.  Returns 0 on success, -1 on error.
 */
static int
vtls_nb_wait(int fd, int events, vtim_real deadline)
{
	struct pollfd pfd[1];
	int i;
	vtim_real now;

	assert(fd >= 0);
	pfd->fd = fd;
	pfd->events = events;

	do {
		now = VTIM_real();
		if (now > deadline) {
			errno = ETIMEDOUT;
			return (-1);
		}
		i = poll(pfd, 1, (deadline - now) * 1000);
	} while (i < 0 && errno == EINTR);
	if (i == 0) {
		errno = ETIMEDOUT;
		return (-1);
	}
	if (i < 0) {
		assert(errno != EWOULDBLOCK);
		return (-1);
	}
	if (!(pfd->revents & events)) {
		errno = EFAULT;
		return (-1);
	}
	return (0);
}

static ssize_t v_matchproto_(vco_nb_read_f)
vtls_nb_read(void *priv, int fd, void *p, size_t l, vtim_real deadline)
{
	struct vtls_sess *tsp;
	int i, e;

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	assert(fd == SSL_get_fd(tsp->ssl));

retry:
	i = SSL_read(tsp->ssl, p, l);
	VTLS_vsl_ssllog(tsp->log);
	e = SSL_get_error(tsp->ssl, i);
	if (e == SSL_ERROR_NONE)
		return (i);
	if (e == SSL_ERROR_ZERO_RETURN)
		return (0);
	if (e == SSL_ERROR_WANT_READ && errno == EWOULDBLOCK)
		return (-1);
	if (e == SSL_ERROR_WANT_WRITE && errno == EWOULDBLOCK) {
		/* The TLS protocol state requires output bytes before we
		 * are able to continue. Wait up until deadline for the
		 * socket to become writable. */
		if (vtls_nb_wait(fd, POLLOUT, deadline))
			return (-1);
		goto retry;
	}
	VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
	return (-1);
}

static ssize_t v_matchproto_(vco_nb_write_f)
vtls_nb_writev(void *priv, int fd, const struct iovec *iov, int n_iov,
    vtim_real deadline)
{
	struct vtls_sess *tsp;
	int i, e;

	/* Note: OpenSSL does not provide a writev()-like function. We
	 * "emulate" writev() functionality by just passing in the first
	 * vector as the argument to SSL_write(). This isn't ideal in the
	 * case of a tiny vector followed by a large one, which often is
	 * the case in H2 where this function is used (9 byte header
	 * followed by a full H2 data frame). Though the only way to
	 * address that would be to memory copy into a large buffer, which
	 * likely would be more expensive. */

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	assert(fd == SSL_get_fd(tsp->ssl));
	assert(n_iov > 0);
	AN(iov);
	assert(iov[0].iov_len > 0);

retry:
	i = SSL_write(tsp->ssl, iov[0].iov_base, iov[0].iov_len);
	VTLS_vsl_ssllog(tsp->log);
	e = SSL_get_error(tsp->ssl, i);
	if (e == SSL_ERROR_NONE)
		return (i);
	if (e == SSL_ERROR_ZERO_RETURN) {
		/* Presumably this can happen when TLS needs to read and
		 * the peer has hung up on us. Set an error to adhere to
		 * the write() like behaviour of this function. */
		VTLS_LOG(tsp->log, SLT_Error, "SSL_write zero return");
		errno = EFAULT;
		return (-1);
	}
	if (e == SSL_ERROR_WANT_WRITE && errno == EWOULDBLOCK)
		return (-1);
	if (e == SSL_ERROR_WANT_READ && errno == EWOULDBLOCK) {
		/* The TLS protocol state requires input bytes before we
		 * are able to continue. Wait up until deadline for the
		 * socket to become readable. */
		if (vtls_nb_wait(fd, POLLIN, deadline))
			return (-1);
		goto retry;
	}
	VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
	return (-1);
}

#define VTLS_OPER(l)						\
static const struct vco vtls_oper_##l = {			\
	.read = vtls_read_##l,					\
	.write = vtls_write,					\
	.writev_prep = vtls_writev_prep,			\
	.writev = vtls_writev,					\
	.nb_read = vtls_nb_read,				\
	.nb_writev = vtls_nb_writev,				\
	.check = vtls_check,					\
};								\
								\
const struct vco *						\
VTLS_conn_oper_##l(struct vtls_sess *tsp, void **ppriv)		\
{								\
	CHECK_OBJ_NOTNULL(tsp, VTLS_SESS_MAGIC);		\
	AN(ppriv);						\
	*ppriv = tsp;						\
	return (&vtls_oper_##l);				\
}

VTLS_OPER(backend)
VTLS_OPER(client)

/*
 * Get TLS session from VRT context.
 * Works for both client (req->sp->tls) and backend (bo->htc->priv->tls) paths.
 */
static struct vtls_sess *
vtls_get_sess(const struct vrt_ctx *ctx)
{
	struct vtls_sess *tsp;
	void *p;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);

	if (ctx->req != NULL) {
		/* Client-side path */
		CHECK_OBJ_NOTNULL(ctx->req, REQ_MAGIC);
		CHECK_OBJ_NOTNULL(ctx->req->sp, SESS_MAGIC);
		CHECK_OBJ_ORNULL(ctx->req->sp->tls, VTLS_SESS_MAGIC);
		return (ctx->req->sp->tls);
	}

	if (ctx->bo != NULL) {
		/* Backend path - get TLS session from connection pool */
		CHECK_OBJ_NOTNULL(ctx->bo, BUSYOBJ_MAGIC);
		if (ctx->bo->htc != NULL && ctx->bo->htc->priv != NULL) {
			p = PFD_TLSPriv(ctx->bo->htc->priv);
			if (p != NULL) {
				CAST_OBJ_NOTNULL(tsp, p, VTLS_SESS_MAGIC);
				return (tsp);
			}
		}
	}

	return (NULL);
}

/* VMOD accessor: get SSL context */
const SSL *
VTLS_tls_ctx(const struct vrt_ctx *ctx)
{
	struct vtls_sess *tsp;

	tsp = vtls_get_sess(ctx);
	if (tsp == NULL)
		return (NULL);

	return (tsp->ssl);
}

/* VMOD accessor: get JA3 fingerprint */
const char *
VTLS_ja3(const struct vrt_ctx *ctx)
{
	struct vtls_sess *tsp;

	tsp = vtls_get_sess(ctx);
	if (tsp == NULL)
		return (NULL);

	return (tsp->ja3);
}

/*
 * This is the SSL_do_handshake/poll loop.
 *
 * The SSL object needs to be initialized and configured via
 * one of SSL_set_accept_state or SSL_set_connect_state
 */
int
VTLS_do_handshake(struct vtls_sess *tsp, int fd, double tmo)
{
	struct pollfd pollone;
	double t_end, t_now;
	int i, t_poll;

	assert(fd > 0);
	CHECK_OBJ_NOTNULL(tsp, VTLS_SESS_MAGIC);
	AZ(isnan(tmo));

	t_end = VTIM_real() + tmo;

	while (1) {
		i = SSL_do_handshake(tsp->ssl);
		if (i > 0) {
			/* Handshake successful */
			break;
		} else if (i == 0) {
			/* Clean protocol handshake failure */
			VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
			return (1);
		}

		switch (SSL_get_error(tsp->ssl, i)) {
		case SSL_ERROR_WANT_READ:
			pollone.events = POLLIN;
			break;
		case SSL_ERROR_WANT_WRITE:
			pollone.events = POLLOUT;
			break;
		default:
			/* Handshake error */
			VTLS_vsl_sslerr(tsp->log, tsp->ssl, i);
			return (1);
		}
		pollone.revents = 0;
		pollone.fd = fd;
		t_now = VTIM_real();
		t_poll = (int)round((t_end - t_now) * 1e3);
		if (t_poll > 0)
			i = poll(&pollone, 1, t_poll);
		if (t_poll <= 0 || i == 0)
			errno = ETIMEDOUT;
		if (t_poll <= 0 || i <= 0) {
			int tag = tsp->log->is_client ? SLT_TLS : SLT_BackendSSL;
			VTLS_LOG(tsp->log, tag, "Handshake timeout");
			VTLS_vsl_ssllog(tsp->log);
			return (1);
		}
	}

	return (0);
}
