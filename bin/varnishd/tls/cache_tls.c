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
#include "cache_tls.h"

#include "vtim.h"

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

	while ((e = ERR_get_error())) {
		ERR_error_string_n(e, buf, sizeof buf);
		VTLS_LOG(log, SLT_BackendSSL, "%s", buf);
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

static ssize_t v_matchproto_(vco_writev_f)
vtls_writev(void *priv, int fd, const struct iovec *iov, int iovcnt)
{
	struct vtls_sess *tsp;
	int i;

	CAST_OBJ_NOTNULL(tsp, priv, VTLS_SESS_MAGIC);
	AN(tsp->ssl);
	assert(fd == SSL_get_fd(tsp->ssl));

	if (iovcnt == 0)
		return (0);

	/*
	 * OpenSSL does not provide a writev()-like function.
	 * We just send the first iovec, and let the caller handle
	 * partial writes by calling us again.
	 */
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

static const struct vco vtls_oper_backend = {
	.read = vtls_read_backend,
	.write = vtls_write,
	.writev = vtls_writev,
	.check = vtls_check,
};

const struct vco *
VTLS_conn_oper_backend(struct vtls_sess *tsp, void **ppriv)
{
	CHECK_OBJ_NOTNULL(tsp, VTLS_SESS_MAGIC);
	AN(ppriv);
	*ppriv = tsp;
	return (&vtls_oper_backend);
}

/*
 * This is the SSL_do_handshake/poll loop.
 *
 * The SSL object needs to be initialized and configured via
 * SSL_set_connect_state (for client/backend connections).
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
			VTLS_LOG(tsp->log, SLT_BackendSSL, "Handshake timeout");
			VTLS_vsl_ssllog(tsp->log);
			return (1);
		}
	}

	return (0);
}
