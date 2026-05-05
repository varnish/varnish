/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2015 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
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
 * HTTP1 Fetch Filters
 *
 * These filters are used for both req.body and beresp.body to handle
 * the HTTP/1 aspects (C-L/Chunked/EOF)
 *
 */

#include "config.h"

#include <inttypes.h>
#include <poll.h>

#include "cache/cache_vinyld.h"
#include "cache/cache_conn_oper.h"
#include "cache/cache_filter.h"
#include "cache_http1.h"

#include "vct.h"
#include "vtcp.h"

#ifndef TEST_DRIVER
static const unsigned max_chunked_hdr = 32;
static ssize_t
v1f_rxbuf_init(struct http_conn *htc)
{

	AZ(htc->rxbuf_b);
	AZ(htc->rxbuf_e);

	htc->rxbuf_b = WS_Alloc(htc->ws, max_chunked_hdr);
	if (htc->rxbuf_b == NULL)
		return (-1);
	htc->rxbuf_e = htc->rxbuf_b + max_chunked_hdr;
	return (0);
}
#endif

/*
 * fill up rxbuf. If there is pipelined data, move it to the beginning and
 * continue reading after it
 */
static ssize_t
v1f_rxbuf_read(const struct vfp_ctx *vc, struct http_conn *htc)
{
	ssize_t i;
	size_t sz;
	char *p;

	if (htc->pipeline_b)
		AN(htc->pipeline_e);
	else
		AZ(htc->pipeline_e);
	AN(htc->rxbuf_b);
	AN(htc->rxbuf_e);

	sz = pdiff(htc->rxbuf_b, htc->rxbuf_e);

	if (htc->pipeline_b == NULL)
		p = htc->pipeline_b = htc->rxbuf_b;
	else {
		AN(htc->pipeline_e);
		i = pdiff(htc->pipeline_b, htc->pipeline_e);
		if (i == sz)
			return (0);
		assert(i >= 0);
		assert((size_t)i < sz);
		memmove(htc->rxbuf_b, htc->pipeline_b, i);
		htc->pipeline_b = htc->rxbuf_b;
		htc->pipeline_e = htc->rxbuf_b + i;
		p = htc->pipeline_e;
		sz -= i;
	}

	do {
		errno = 0;
		i = htc->oper->read(htc->oper_priv, *htc->rfd, p, sz);
	} while (i < 0 && errno == EINTR);
	if (i < 0) {
		VCO_Assert(htc->oper, i);
		VSLbs(vc->wrk->vsl, SLT_FetchError,
		    TOSTRAND(VAS_errtxt(errno)));
		return (i);
	}
	htc->pipeline_e = p + i;
	if (htc->pipeline_b == htc->pipeline_e)
		 htc->pipeline_b = htc->pipeline_e = NULL;
	return (i);
}

#ifdef TEST_DRIVER

#include <stdio.h>

void
VSLbs(struct vsl_log *vsl, enum VSL_tag_e tag, const struct strands *s)
{
	(void)vsl;
	(void)tag;
	(void)s;
}

static ssize_t
t_vco_read(void *priv, int fd, void *buf, size_t len)
{
	(void)priv;
	return (read(fd, buf, len));
}

static int
t_vco_check(ssize_t a)
{
	return (a >= 0);
}

static const struct vco t_vco = {
	.read = t_vco_read,
	.check = t_vco_check,
};

/*
static ssize_t
v1f_rxbuf_read(const struct vfp_ctx *vc, struct http_conn *htc);
*/
static void
t_rxbuf_read(void) {
	struct http_conn htc[1];
	const char *data = "0123456789abcdef";
	char rxbuf[16];
	int fd[2], i, r;

	assert(strlen(data) == sizeof rxbuf);

	INIT_OBJ(htc, HTTP_CONN_MAGIC);
	// v1f_rxbuf_init without the workspace
	htc->rxbuf_b = rxbuf;
	htc->rxbuf_e = htc->rxbuf_b + sizeof rxbuf;
	htc->oper = &t_vco;

	AZ(pipe(fd));
	htc->rfd = &fd[0];

	for (i = 0; i < strlen(data); i++) {
		r = write(fd[1], data + i, 1);
		assert(r == 1);
		r = v1f_rxbuf_read(NULL, htc);
		assert(r == 1);
		size_t av = pdiff(htc->pipeline_b, htc->pipeline_e);
		assert(av == i + 1);
		AZ(memcmp(htc->pipeline_b, data, av));
		if (i % 2 == 0) {
			// v1f_rxbuf_read moves pipelined data to the beginning
			assert(htc->pipeline_b == htc->rxbuf_b);
			memmove(htc->pipeline_b + 1, htc->pipeline_b, av);
			htc->pipeline_b++;
			htc->pipeline_e++;
		}

	}
	// buffer is now full
	AZ(v1f_rxbuf_read(NULL, htc));

	close(fd[0]);
	close(fd[1]);
}

int
main(int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	printf("-- rxbuf_read\n");
	t_rxbuf_read();

	printf("OK\n");
	return (0);
}
#else

/*--------------------------------------------------------------------
 * Read up to len bytes, returning pipelined data first.
 */

static ssize_t
v1f_read(const struct vfp_ctx *vc, struct http_conn *htc, void *d, ssize_t len)
{
	ssize_t l;
	unsigned char *p;
	ssize_t i;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(htc, HTTP_CONN_MAGIC);
	assert(len > 0);
	l = 0;
	p = d;
	// XXX temp v1f_chunked_hdr caller signal
	if (len == 1 && htc->pipeline_b == NULL && htc->rxbuf_b == NULL) {
		i = v1f_rxbuf_init(htc);
		if (i) {
			VSLb(vc->wrk->vsl, SLT_FetchError, "No workspace for rxbuf");
			return (i);
		}
	}
	if (len == 1 && htc->pipeline_b == NULL && htc->rxbuf_b != NULL) {
		i = v1f_rxbuf_read(vc, htc);
		if (i < 0)
			return (i);
	}
	i = 0;
	if (htc->pipeline_b) {
		l = htc->pipeline_e - htc->pipeline_b;
		assert(l > 0);
		l = vmin(l, len);
		memcpy(p, htc->pipeline_b, l);
		p += l;
		len -= l;
		htc->pipeline_b += l;
		if (htc->pipeline_b == htc->pipeline_e)
			htc->pipeline_b = htc->pipeline_e = NULL;
	}
	if (len > 0) {
		do {
			errno = 0;
			i = htc->oper->read(htc->oper_priv, *htc->rfd, p, len);
		} while (i < 0 && errno == EINTR);
		if (i < 0) {
			VCO_Assert(htc->oper, i);
			VSLbs(vc->wrk->vsl, SLT_FetchError,
			    TOSTRAND(VAS_errtxt(errno)));
			return (i);
		}
		assert(i <= len);
	}
	assert(i >= 0);
	assert(l >= 0);
	assert(i < SSIZE_MAX / 2);
	assert(l < SSIZE_MAX / 2);
	return (i + l);
}


/*--------------------------------------------------------------------
 * read (CR)?LF at the end of a chunk
 */
static enum vfp_status
v1f_chunk_end(struct vfp_ctx *vc, struct http_conn *htc)
{
	char c;

	if (v1f_read(vc, htc, &c, 1) <= 0)
		return (VFP_Error(vc, "chunked read err"));
	if (c == '\r' && v1f_read(vc, htc, &c, 1) <= 0)
		return (VFP_Error(vc, "chunked read err"));
	if (c != '\n')
		return (VFP_Error(vc, "chunked tail no NL"));
	return (VFP_OK);
}


/*--------------------------------------------------------------------
 * Parse a chunk header and, for VFP_OK, return size in a pointer
 *
 * XXX: Reading one byte at a time is pretty pessimal.
 */

static enum vfp_status
v1f_chunked_hdr(struct vfp_ctx *vc, struct http_conn *htc, ssize_t *szp)
{
	char buf[20];		/* XXX: 20 is arbitrary */
	unsigned u;
	uintmax_t cll;
	ssize_t cl, lr;
	char *q;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(htc, HTTP_CONN_MAGIC);
	AN(szp);
	assert(*szp == -1);

	/* Skip leading whitespace */
	do {
		lr = v1f_read(vc, htc, buf, 1);
		if (lr <= 0)
			return (VFP_Error(vc, "chunked read err"));
	} while (vct_isows(buf[0]));

	if (!vct_ishex(buf[0]))
		return (VFP_Error(vc, "chunked header non-hex"));

	/* Collect hex digits, skipping leading zeros */
	for (u = 1; u < sizeof buf; u++) {
		do {
			lr = v1f_read(vc, htc, buf + u, 1);
			if (lr <= 0)
				return (VFP_Error(vc, "chunked read err"));
		} while (u == 1 && buf[0] == '0' && buf[u] == '0');
		if (!vct_ishex(buf[u]))
			break;
	}

	if (u >= sizeof buf)
		return (VFP_Error(vc, "chunked header too long"));

	/* Skip trailing white space */
	while (vct_isows(buf[u])) {
		lr = v1f_read(vc, htc, buf + u, 1);
		if (lr <= 0)
			return (VFP_Error(vc, "chunked read err"));
	}

	if (buf[u] == '\r' && v1f_read(vc, htc, buf + u, 1) <= 0)
		return (VFP_Error(vc, "chunked read err"));
	if (buf[u] != '\n')
		return (VFP_Error(vc, "chunked header no NL"));

	buf[u] = '\0';

	cll = strtoumax(buf, &q, 16);
	if (q == NULL || *q != '\0')
		return (VFP_Error(vc, "chunked header number syntax"));
	cl = (ssize_t)cll;
	if (cl < 0 || (uintmax_t)cl != cll)
		return (VFP_Error(vc, "bogusly large chunk size"));

	*szp = cl;
	return (VFP_OK);
}


/*--------------------------------------------------------------------
 * Check if data is available
 */

static int
v1f_poll(const struct http_conn *htc)
{
	struct pollfd pfd[1];
	int r;

	CHECK_OBJ_NOTNULL(htc, HTTP_CONN_MAGIC);

	if (htc->pipeline_b)
		return (1);

	pfd->fd = *htc->rfd;
	pfd->events = POLLIN;

	r = poll(pfd, 1, 0);
	if (r < 0) {
		assert(errno == EINTR);
		return (0);
	}
	if (r == 0)
		return (0);
	assert(r == 1);
	assert(pfd->revents & POLLIN);
	return (1);
}


/*--------------------------------------------------------------------
 * Read a chunked HTTP object.
 *
 */

static enum vfp_status v_matchproto_(vfp_pull_f)
v1f_chunked_pull(struct vfp_ctx *vc, struct vfp_entry *vfe, void *ptr,
    ssize_t *lp)
{
	enum vfp_status vfps;
	struct http_conn *htc;
	ssize_t l, lr;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
	CAST_OBJ_NOTNULL(htc, vfe->priv1, HTTP_CONN_MAGIC);
	AN(ptr);
	AN(lp);

	l = *lp;
	*lp = 0;
	if (vfe->priv2 == -1) {
		vfps = v1f_chunked_hdr(vc, htc, &vfe->priv2);
		if (vfps != VFP_OK)
			return (vfps);
	}
	if (vfe->priv2 > 0) {
		if (vfe->priv2 < l)
			l = vfe->priv2;
		lr = v1f_read(vc, htc, ptr, l);
		if (lr <= 0)
			return (VFP_Error(vc, "chunked insufficient bytes"));
		*lp = lr;
		vfe->priv2 -= lr;
		if (vfe->priv2 != 0)
			return (VFP_OK);

		vfe->priv2 = -1;

		vfps = v1f_chunk_end(vc, htc);
		if (vfps != VFP_OK)
			return (vfps);

		/* only if some data of the next chunk header is available, read
		 * it to check if we can return VFP_END */
		if (! v1f_poll(htc))
			return (VFP_OK);
		vfps = v1f_chunked_hdr(vc, htc, &vfe->priv2);
		if (vfps != VFP_OK)
			return (vfps);
		if (vfe->priv2 != 0)
			return (VFP_OK);
	}
	AZ(vfe->priv2);
	vfps = v1f_chunk_end(vc, htc);
	return (vfps == VFP_OK ? VFP_END : vfps);
}

static const struct vfp v1f_chunked = {
	.name = "V1F_CHUNKED",
	.pull = v1f_chunked_pull,
};


/*--------------------------------------------------------------------*/

static enum vfp_status v_matchproto_(vfp_pull_f)
v1f_straight_pull(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p,
    ssize_t *lp)
{
	ssize_t l, lr;
	struct http_conn *htc;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
	CAST_OBJ_NOTNULL(htc, vfe->priv1, HTTP_CONN_MAGIC);
	AN(p);
	AN(lp);

	l = *lp;
	*lp = 0;

	if (vfe->priv2 == 0) // XXX: Optimize Content-Len: 0 out earlier
		return (VFP_END);
	l = vmin(l, vfe->priv2);
	lr = v1f_read(vc, htc, p, l);
	if (lr <= 0)
		return (VFP_Error(vc, "straight insufficient bytes"));
	*lp = lr;
	vfe->priv2 -= lr;
	if (vfe->priv2 == 0)
		return (VFP_END);
	return (VFP_OK);
}

static const struct vfp v1f_straight = {
	.name = "V1F_STRAIGHT",
	.pull = v1f_straight_pull,
};

/*--------------------------------------------------------------------*/

static enum vfp_status v_matchproto_(vfp_pull_f)
v1f_eof_pull(struct vfp_ctx *vc, struct vfp_entry *vfe, void *p, ssize_t *lp)
{
	ssize_t l, lr;
	struct http_conn *htc;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vfe, VFP_ENTRY_MAGIC);
	CAST_OBJ_NOTNULL(htc, vfe->priv1, HTTP_CONN_MAGIC);
	AN(p);

	AN(lp);

	l = *lp;
	*lp = 0;
	lr = v1f_read(vc, htc, p, l);
	if (lr < 0)
		return (VFP_Error(vc, "eof socket fail"));
	if (lr == 0) {
		htc->doclose = SC_RESP_CLOSE;
		return (VFP_END);
	}
	*lp = lr;
	return (VFP_OK);
}

static const struct vfp v1f_eof = {
	.name = "V1F_EOF",
	.pull = v1f_eof_pull,
};

/*--------------------------------------------------------------------
 */

int
V1F_Setup_Fetch(struct vfp_ctx *vfc, struct http_conn *htc)
{
	struct vfp_entry *vfe;

	CHECK_OBJ_NOTNULL(vfc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(htc, HTTP_CONN_MAGIC);

	AN(htc->ws);
	AZ(htc->ws->r);

	AZ(htc->rxbuf_b);
	AZ(htc->rxbuf_e);

	if (htc->body_status == BS_EOF) {
		assert(htc->content_length == -1);
		vfe = VFP_Push(vfc, &v1f_eof);
		if (vfe == NULL)
			return (ENOSPC);
		vfe->priv2 = 0;
	} else if (htc->body_status == BS_LENGTH) {
		assert(htc->content_length > 0);
		vfe = VFP_Push(vfc, &v1f_straight);
		if (vfe == NULL)
			return (ENOSPC);
		vfe->priv2 = htc->content_length;
	} else if (htc->body_status == BS_CHUNKED) {
		assert(htc->content_length == -1);
		vfe = VFP_Push(vfc, &v1f_chunked);
		if (vfe == NULL)
			return (ENOSPC);
		vfe->priv2 = -1;
	} else {
		WRONG("Wrong body_status");
	}
	vfe->priv1 = htc;
	return (0);
}
#endif
