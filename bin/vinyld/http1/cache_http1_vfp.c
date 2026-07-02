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

static const unsigned max_chunked_hdr = 32;	// adjust b00007.vtc if changed

#ifndef TEST_DRIVER
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
v1f_rxbuf_read(struct http_conn *htc)
{
	ssize_t i;
	size_t av, sz;
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
		av = pdiff(htc->pipeline_b, htc->pipeline_e);
		if (av >= sz) {
			// VTCP_Check(): can not originate from read()
			errno = ENOBUFS;
			return (-1);
		}
		assert(av < sz);
		memmove(htc->rxbuf_b, htc->pipeline_b, av);
		htc->pipeline_b = htc->rxbuf_b;
		htc->pipeline_e = htc->rxbuf_b + av;
		p = htc->pipeline_e;
		sz -= av;
	}
	do {
		errno = 0;
		i = htc->oper->read(htc->oper_priv, *htc->rfd, p, sz);
	} while (i < 0 && errno == EINTR);
	if (i < 0) {
		VCO_Assert(htc->oper, i);
		return (i);
	}
	htc->pipeline_e = p + i;
	if (htc->pipeline_b == htc->pipeline_e)
		 htc->pipeline_b = htc->pipeline_e = NULL;
	return (i);
}

/*--------------------------------------------------------------------
 * Parse a chunk tail in the pipeline and return status as appropriate
 */
struct pct { const char *msg; };

static struct pct pct_more[]	= {{"tail more"}};
static struct pct pct_nonl[]	= {{"chunked tail no NL"}};

// the unused parameter is to simplify the macro calling different parsers
static struct pct *
v1f_parse_chunked_tail(char *b, const char *e, void *unused, char **nextp)
{
	AN(b);
	AN(e);
	(void)unused;
	AN(nextp);

	if (b == e)
		return (pct_more);
	if (*b == '\r')
		b++;
	if (b == e)
		return (pct_more);
	if (*b != '\n')
		return (pct_nonl);
	b++;

	*nextp = b;
	return (NULL);
}


/*--------------------------------------------------------------------
 * Parse a chunk header in the pipeline and return status as appropriate
 */

struct pch { const char *msg; };

static struct pch pch_more[]	= {{"more"}};
static struct pch pch_nonhex[]	= {{"chunked header non-hex"}};
static struct pch pch_nonl[]	= {{"chunked header no NL"}};
static struct pch pch_syntax[]	= {{"chunked header number syntax"}}; // can't happen?
static struct pch pch_large[]	= {{"bogusly large chunk size"}};
static struct pch pch_toolong[]	= {{"chunked header too long"}};

static struct pch *
v1f_parse_chunked_hdr_i(char *b, const char *e, ssize_t *szp, char **nextp)
{
	char *hb, *he, *q, s;
	uintmax_t cll;
	ssize_t cl;

	AN(b);
	AN(e);
	AN(szp);
	AN(nextp);

	/* Skip leading whitespace - XXX rfc9112 does not specify this */
	while (b < e && vct_isows(*b))
		b++;
	if (b == e)
		return (pch_more);
	if (!vct_ishex(*b))
		return (pch_nonhex);
	/* Skip leading zeros */
	while (b < e - 1 && b[0] == '0' && b[1] == '0')
		b++;
	if (b == e)
		return (pch_more);
	hb = b;
	/* Collect hex digits */
	while (b < e && vct_ishex(*b))
		b++;
	if (b == e)
		return (pch_more);
	he = b;
	/* Skip trailing whitespace. XXX rfc9112 does not specify this
	 * XXX extension support missing https://httpwg.org/specs/rfc9112.html#chunked.extension
	 */
	while (b < e && vct_isows(*b))
		b++;
	if (b == e)
		return (pch_more);
	if (*b == '\r')
		b++;
	if (b == e)
		return (pch_more);
	if (*b != '\n')
		return (pch_nonl);
	b++;

	errno = 0;
	s = *he;
	*he = '\0';
	cll = strtoumax(hb, &q, 16);
	// restore original for debug-/testability
	*he = s;

	if (q == NULL || q != he)
		return (pch_syntax);

	cl = (ssize_t)cll;
	if (cl < 0 || (uintmax_t)cl != cll)
		return (pch_large);

	// for a number larger than ULLONG_MAX, strtoumax() returns
	// ULLONG_MAX and sets errno to ERANGE. We catch this with the above
	// check already, but assert that we really do
	AZ(errno);

	*szp = cl;
	*nextp = b;
	return (NULL);
}

// length check outside the actual parser for clarity
static struct pch *
v1f_parse_chunked_hdr(char *b, const char *e, ssize_t *szp, char **nextp)
{
	static struct pch *r;
	const char *ee;

	ee = vmin_t(const char *, e, b + max_chunked_hdr);

	r = v1f_parse_chunked_hdr_i(b, ee, szp, nextp);

	if (r == pch_more && e != ee)
		return (pch_toolong);

	return (r);
}

#ifdef TEST_DRIVER

#include <stdlib.h>
#include <stdio.h>

// positive test cases have three constituents, we permutate all of them
static const char *t_ok_pre[] = {
	"",
	" ",
	"\t",
	" \t0",
	"00"
};

static const uintmax_t t_ok_sz[] = {
	0,
	1,
	0xa,
	0x10,
	0xaffe,
	SSIZE_MAX
};

static const char *t_ok_post[] = {
	"\r\n",
	"\n",
	" \r\n",
	" \t\n",
};

static const char *t_ok_next[] = {
	"",
	"\r\n",
	"\n",
	"GET",
	"\r\n01234567",
};

struct pch_neg {
	struct pch *r;
	const char *hdr;
};

// negative tests
static struct pch_neg t_neg[] = {
	{pch_more, ""},
	{pch_more, "\t "},

	{pch_nonhex, "x"},
	{pch_nonhex, " x"},
	{pch_nonhex, "\n"},
	{pch_nonhex, "\r"},

	{pch_more, "000"},
	{pch_more, "affe"},
	{pch_more, " a\r"},

	{pch_nonl, " a\rx"},
	{pch_nonl, " ax"},

	{pch_large, "8000000000000000\r\n"},
	{pch_large, "800000000000000000000000\r\n"},
};

// tail
static const char *t_ok_tail[] = {
	"\r\n",
	"\n",
};

static const char *t_ok_tail_next[] = {
	"",
	"0123",
};

struct pct_neg {
	struct pct *r;
	const char *hdr;
};

static struct pct_neg t_neg_tail[] = {
	{pct_more, "\r"},
	{pct_nonl, "\rx"},
};


static void
t_parse_chunked_hdr(char *b, char *e,
    const struct pch *r_exp, ssize_t sz_exp, const char *next_exp)
{
	const struct pch *r;
	char *next = NULL;
	ssize_t sz = -1;
	r = v1f_parse_chunked_hdr(b, e, &sz, &next);
#ifdef DEBUG
	printf("r = %s, sz = 0x%zx, n = %s\n", r ? r->msg : "NULL", sz,
	    next ? next : "NULL");
#endif
	assert(r == r_exp);
	assert(sz == sz_exp);
	assert(next == next_exp);
}

static void
t_parse_chunked_hdr_err(char *b, char *e, const struct pch *err)
{
	t_parse_chunked_hdr(b, e, err, -1, NULL);
}

static void
t_parse_chunked_hdr_ok(char *b, char *e,
    ssize_t sz_exp, const char *next_exp)
{
	t_parse_chunked_hdr(b, e, NULL, sz_exp, next_exp);
}

static void
t_parse_chunked_tail(char *b, char *e,
    const struct pct *r_exp, const char *next_exp)
{
	const struct pct *r;
	char *next = NULL;
	r = v1f_parse_chunked_tail(b, e, NULL, &next);
#ifdef DEBUG
	printf("r = %s, n = %s\n", r ? r->msg : "NULL",
	    next ? next : "NULL");
#endif
	assert(r == r_exp);
	assert(next == next_exp);
}

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
v1f_rxbuf_read(struct http_conn *htc);
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
		r = v1f_rxbuf_read(htc);
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
	r = v1f_rxbuf_read(htc);
	assert(r == -1);
	assert(errno == ENOBUFS);

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

	printf("-- head postitive test permutations\n");
	// avoid nested loops
	unsigned n_ok = vcountof(t_ok_pre) * vcountof(t_ok_sz) *
	    vcountof(t_ok_post) * vcountof(t_ok_next);
	char buf[80];
	for (unsigned n = 0; n < n_ok; n++) {
		unsigned n_pre = n % vcountof(t_ok_pre);
		unsigned n_sz = n / vcountof(t_ok_pre);
		unsigned n_post = n_sz / vcountof(t_ok_sz);
		unsigned n_next = n_post / vcountof(t_ok_post);
		n_sz %= vcountof(t_ok_sz);
		n_post %= vcountof(t_ok_post);
		assert(n_next < vcountof(t_ok_next));

#ifdef DEBUG
		printf("n_next=%u n_post=%u n_sz=%u n_pre=%u\n",
		    n_next, n_post, n_sz, n_pre);
#endif
		bprintf(buf, "%s%jx%s%s", t_ok_pre[n_pre], t_ok_sz[n_sz],
		    t_ok_post[n_post], t_ok_next[n_next]);

		char *ee = buf + strlen(buf) - strlen(t_ok_next[n_next]);

		for (char *e = buf; e < ee; e++)
			t_parse_chunked_hdr_err(buf, e, pch_more);

		t_parse_chunked_hdr_ok(buf, ee, t_ok_sz[n_sz], ee);
	}

	printf("-- head negative tests\n");
	for (struct pch_neg *neg = t_neg; neg < t_neg + vcountof(t_neg); neg++) {
		size_t l = strlen(neg->hdr);
		assert(l < sizeof buf);

		memcpy(buf, neg->hdr, l + 1);
		char *e = buf + l;

		t_parse_chunked_hdr_err(buf, e, neg->r);
	}

	printf("-- tail postitive test permutations\n");
	n_ok = vcountof(t_ok_tail) * vcountof(t_ok_tail_next);
	for (unsigned n = 0; n < n_ok; n++) {
		unsigned n_tail = n % vcountof(t_ok_tail);
		unsigned n_next = n / vcountof(t_ok_tail_next);
		assert(n_next < vcountof(t_ok_tail_next));

		bprintf(buf, "%s%s", t_ok_tail[n_tail], t_ok_tail_next[n_next]);
		char *ee = buf + strlen(buf) - strlen(t_ok_tail_next[n_next]);

		for (char *e = buf; e < ee; e++)
			t_parse_chunked_tail(buf, e, pct_more, NULL);

		t_parse_chunked_tail(buf, ee, NULL, ee);
	}

	printf("-- tail negative tests\n");
	for (struct pct_neg *neg = t_neg_tail; neg < t_neg_tail + vcountof(t_neg_tail); neg++) {
		size_t l = strlen(neg->hdr);
		assert(l < sizeof buf);

		memcpy(buf, neg->hdr, l + 1);
		char *e = buf + l;

		t_parse_chunked_tail(buf, e, neg->r, NULL);
	}

	printf("OK\n");
	return (0);
}
#else

/*--------------------------------------------------------------------
 * Read up to len bytes, returning pipelined data first.
 */

enum ahead {
	NO_READ_AHEAD,
	READ_AHEAD
};

static ssize_t
v1f_readahead(struct http_conn *htc, unsigned char *p, ssize_t len)
{
	struct iovec iov[2];
	ssize_t i;

	AZ(htc->pipeline_b);
	if (htc->rxbuf_b == NULL && v1f_rxbuf_init(htc)) {
		errno = ENOMEM;
		return (-ENOMEM);
	}
	AN(htc->rxbuf_b);

	iov[0].iov_base = p;
	iov[0].iov_len = len;
	iov[1].iov_base = htc->rxbuf_b;
	iov[1].iov_len = pdiff(htc->rxbuf_b, htc->rxbuf_e);

	i = readv(*htc->rfd, iov, vcountof(iov));
	if (i <= len)
		return (i);
	i -= len;
	htc->pipeline_b = htc->rxbuf_b;
	htc->pipeline_e = htc->rxbuf_b + i;

	return (len);
}

static ssize_t
v1f_read(const struct vfp_ctx *vc, struct http_conn *htc, void *d, ssize_t len,
    enum ahead ahead)
{
	ssize_t l;
	unsigned char *p;
	ssize_t i;

	CHECK_OBJ_NOTNULL(vc, VFP_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(htc, HTTP_CONN_MAGIC);
	assert(len > 0);
	l = 0;
	p = d;
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
			if (ahead == READ_AHEAD && htc->oper == VCO_default)
				i = v1f_readahead(htc, p, len);
			else
				i = htc->oper->read(htc->oper_priv, *htc->rfd, p, len);
		} while (i < 0 && errno == EINTR);
		if (i < 0) {
			if (ahead == NO_READ_AHEAD || htc->oper != VCO_default ||
			    i != -ENOMEM)
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

static enum vfp_status
v1f_ok(struct http_conn *htc)
{
	if ((htc)->pipeline_b == (htc)->pipeline_e)
		(htc)->pipeline_b = (htc)->pipeline_e = NULL;
	return (VFP_OK);
}


/*--------------------------------------------------------------------
 * Call parser on pipeline:
 * - If pipeline filled, try to return a parse result without reading
 * - else read until either the rxbuf is filled, or we have a parse
 *
 * this is a macro because the code for calling the head and tail parser is
 * _almost_ (but not quite) identical
 */

#define CHUNKED_PARSER(vc, htc, func, func_arg, more, what)			\
										\
	ssize_t sz;								\
										\
	if ((htc)->pipeline_b) {						\
		r = func((htc)->pipeline_b, (htc)->pipeline_e,			\
			func_arg, &(htc)->pipeline_b);				\
		if (r == NULL)							\
			return (v1f_ok(htc));					\
		if (r != more)							\
			return (VFP_Error(vc, "%s", r->msg));			\
	}									\
	if ((htc)->rxbuf_b == NULL && v1f_rxbuf_init(htc) != 0)			\
		return (VFP_Error(vc, "No workspace for rxbuf"));		\
	while ((sz = v1f_rxbuf_read(htc)) > 0) {				\
		r = func((htc)->pipeline_b, (htc)->pipeline_e,			\
		    func_arg, &(htc)->pipeline_b);				\
		if (r == NULL)							\
			return (v1f_ok(htc));					\
		if (r == more)							\
			continue;						\
		VSLb((vc)->wrk->vsl, SLT_Debug, "%.*s",				\
		    (int)pdiff((htc)->pipeline_b, (htc)->pipeline_e),		\
		    (htc)->pipeline_b);						\
		return (VFP_Error(vc, "%s", r->msg));				\
	}									\
	if (sz == 0)								\
		return (VFP_Error(vc, "chunked " what " EOF"));			\
	assert(sz < 0);								\
	VSLbs(vc->wrk->vsl, SLT_FetchError, TOSTRAND(VAS_errtxt(errno)));	\
	return (VFP_Error(vc, "^^^ error reading chunk " what));

/*--------------------------------------------------------------------
 * read (CR)?LF at the end of a chunk
 */

static enum vfp_status
v1f_chunk_end(struct vfp_ctx *vc, struct http_conn *htc)
{
	const struct pct *r;
	CHUNKED_PARSER(vc, htc, v1f_parse_chunked_tail, NULL, pct_more, "tail")
}

/*--------------------------------------------------------------------
 * Parse a chunk header and, for VFP_OK, return size in a pointer
 */

static enum vfp_status
v1f_chunked_hdr(struct vfp_ctx *vc, struct http_conn *htc, ssize_t *szp)
{
	const struct pch *r;
	CHUNKED_PARSER(vc, htc, v1f_parse_chunked_hdr, szp, pch_more, "header")
}

#undef CHUNKED_PARSER

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
		if (vfe->priv2 <= l) {
			l = vfe->priv2;
			lr = v1f_read(vc, htc, ptr, l, READ_AHEAD);
		} else
			lr = v1f_read(vc, htc, ptr, l, NO_READ_AHEAD);
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

		/* opportunistically check for next chunk header read ahead */
		if (! htc->pipeline_b)
			return (VFP_OK);

		const struct pch *r = v1f_parse_chunked_hdr(
		    htc->pipeline_b, htc->pipeline_e,
		    &vfe->priv2, &htc->pipeline_b);
		if (r == pch_more)
			return (VFP_OK);
		if (r != NULL)
			return (VFP_Error(vc, "%s", r->msg));
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
	lr = v1f_read(vc, htc, p, l, NO_READ_AHEAD);
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
	lr = v1f_read(vc, htc, p, l, NO_READ_AHEAD);
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
