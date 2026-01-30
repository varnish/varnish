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
 * TLS support (backend and client-side)
 */

/* Forward declaration - OpenSSL types */
typedef struct ssl_st SSL;

struct mempool;
struct pool;
struct vco;
struct vrt_ctx;
struct vsl_log;

/*
 * struct vtls_log is used for unified logging across TLS operations.
 *
 * We need to support:
 *  - backend probes (non-transactional, vxid = 0, no vsl buf)
 *  - TLS handshake
 *    - client: SLT_TLS: logged to session, no vsl buf
 *    - backend: SLT_BackendSSL: logged to vsl buf
 *  - write/writev/read: client-side logs SLT_TLS, backend logs SLT_BackendSSL
 *
 * The is_client flag decides which tag is used.
 */

struct vtls_log {
	struct vsl_log		*vsl;
	vxid_t			vxid;
	unsigned		is_client;
};

/*
 * TLS record buffer for client-side TLS.
 * Used to handle TLS record boundaries when needed.
 */
struct vtls_buf {
	unsigned		magic;
#define VTLS_BUF_MAGIC		0xfb745381
	unsigned		buflen;
	struct mempool		*pool;
	char			bytes[];
};

/*
 * Per-connection TLS session state
 */
struct vtls_sess {
	unsigned		magic;
#define VTLS_SESS_MAGIC		0x4795576c

	SSL			*ssl;
	struct vtls_log		log[1];

	/* Client-side TLS fields */
	int			sni_result;	/* SNI callback result */
	char			*ja3;		/* JA3 fingerprint string */
	struct vtls_buf		*buf;		/* TLS record buffer */
	void			*priv_local;	/* Pointer to listen_sock->tls */
};

/* TLS VCO provider for backend connections */
const struct vco *VTLS_conn_oper_backend(struct vtls_sess *tsp, void **ppriv);

/* TLS VCO provider for client connections */
const struct vco *VTLS_conn_oper_client(struct vtls_sess *tsp, void **ppriv);

/* Initialize TLS buffer pool for a worker pool */
void VTLS_NewPool(struct pool *pp, unsigned pool_no);

/* Logging helpers */
void VTLS_flush_errors(void);
void VTLS_vsl_ssllog(struct vtls_log *log);
void VTLS_vsl_sslerr(struct vtls_log *log, SSL *ssl, int i);

/* TLS handshake with poll loop */
int VTLS_do_handshake(struct vtls_sess *tsp, int fd, double tmo);

/* TLS buffer management */
struct vtls_buf *VTLS_buf_alloc(struct mempool *mpl_ssl);
void VTLS_buf_free(struct vtls_buf **pbuf);
void VTLS_buf_release(struct vtls_sess *tsp);

/* Client-side TLS session management */
void VTLS_del_sess(struct pool *pp, struct vtls_sess **ptsp);
void VTLS_vsl_set(struct vtls_sess *tsp, struct vsl_log *vsl);

/* Certificate initialization (child process) */
void VTLS_tls_cert_init(void);

/* TLS transport */
extern struct transport TLS_transport;

/* VMOD accessor functions */
const SSL *VTLS_tls_ctx(const struct vrt_ctx *ctx);
const char *VTLS_ja3(const struct vrt_ctx *ctx);

/* Log message macro - if vsl is NULL it is logged as non-transactional */
#define VTLS_LOG(log, tag, ...)					\
	do {							\
		if ((log)->vsl)					\
			VSLb((log)->vsl, tag, __VA_ARGS__);	\
		else						\
			VSL(tag, (log)->vxid, __VA_ARGS__);	\
	} while (0)
