/*-
 * Copyright 2026 UPLEX - Nils Goroll Systemtoptimierung
 * All rights reserved.
 *
 * Author: Nils Goroll <nils.goroll@uplex.de>
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
 * Mocking for minimal VDPIO testing/fuzzing
 */

#include "config.h"

//lint -e766
//lint -e801 goto

#include <stdlib.h>
#include <stdio.h>

#include "cache_int.h"
#include "cache_filter.h"
#include "cache_objhead.h"
#include "cache_vgz.h"

#include "vfil.h"
#include "vrnd.h"
#include "vtim.h"

#include "storage/storage.h"
#include "storage/storage_vai.h"

#include "vdpio_test.h"

#ifdef VDPIO_TEST_DRIVER

enum mock_flags {
	MF_LATE_END =	1,	// send VSCARAB_F_END after all data
	MF_EMPTY_VIOV =	1U<<1,	// lease must be returned
	MF_OK_LIM,
	// can not be combined with other flags
	MF_ERROR =	1U<<16
};


struct VSC_main *VSC_C_main = &(struct VSC_main){};
//lint -esym(843, cache_param)
//lint -esym(844, cache_param)
volatile struct params *cache_param = &(struct params){};
void
VSLb(struct vsl_log *vsl, enum VSL_tag_e tag, const char *fmt, ...) {
	va_list ap;

	(void)vsl;
	(void)tag;
	va_start(ap, fmt);
	(void)vprintf(fmt, ap);
	printf("\n");
	va_end(ap);
}
void
WRK_Log(enum VSL_tag_e tag, const char *fmt, ...) {
	(void)tag;
	(void)fmt;
}
int
PAN__DumpStruct(struct vsb *vsb, int block, int track, const void *ptr,
    const char *smagic, unsigned magic, const char *fmt, ...) {
	(void)vsb;
	(void)block;
	(void)track;
	(void)ptr;
	(void)smagic;
	(void)magic;
	(void)fmt;
	return (0);
}
void
http_Unset(struct http *hp, hdr_t hdr) {
	(void)hp;
	(void)hdr;
}
struct boc *
HSH_RefBoc(const struct objcore *oc) {
	(void)oc;
	return (NULL);
}
void
HSH_DerefBoc(struct worker *wrk, struct objcore *oc)
{
	(void)wrk;
	(void)oc;
}
void
HSH_Cancel(struct worker *wrk, struct objcore *oc, struct boc *boc)
{
	(void)wrk;
	(void)oc;
	(void)boc;
}
int
ObjIterate(struct worker *wrk, struct objcore *oc,
    void *priv, objiterate_f *func, int final)
{
	(void)wrk;
	(void)oc;
	(void)priv;
	(void)func;
	(void)final;
	return (1);
}

// cache_http.c
#define HTTPH(a, b, c) hdr_t b = HDR(a);
#include "tbl/http_headers.h"

const void *
ObjGetAttr(struct worker *wrk, struct objcore *oc, enum obj_attr attr,
   ssize_t *len)
{
	(void)wrk;
	(void)oc;
	(void)attr;
	(void)len;
	return (NULL);
}

struct mockbuf {
	unsigned		magic;
#define MOCKBUF_MAGIC		0x78d40433
	size_t			sz;
	VTAILQ_ENTRY(mockbuf)	list;
	char			bytes[];
};

struct mockstats {
	unsigned		again;
	unsigned		nobufs;
};

struct mockhdl {
	unsigned		magic;
#define MOCKHDL_MAGIC		0xbbf5bb65

	char			*body;
	size_t			body_len;

	size_t			leased;

	unsigned		nleased;	// outstanding non-buffers
	VTAILQ_HEAD(,mockbuf)	bufhead;

	unsigned		mf;

	// injection
	int			error_lease;
	int			error_buffer;
	size_t			inject_at;

	struct mockstats	s_lease, s_buffer;

	// notification
	pthread_mutex_t		mtx;
	pthread_cond_t		cond;
	unsigned		posted;
	unsigned		running;
};

static void *
notify_thread(void *priv)
{
	struct mockhdl *hdl;

	CAST_OBJ_NOTNULL(hdl, priv, MOCKHDL_MAGIC);

	usleep(100);
	ObjVAInotify(NULL, priv);
	PTOK(pthread_mutex_lock(&hdl->mtx));
	AN(hdl->running--);
	PTOK(pthread_mutex_unlock(&hdl->mtx));
	return (NULL);
}

static void
notify(vai_hdl vhdl)
{
	struct mockhdl *hdl;
	pthread_attr_t attr;
	pthread_t thr;

	CAST_OBJ_NOTNULL(hdl, vhdl, MOCKHDL_MAGIC);
	PTOK(pthread_mutex_lock(&hdl->mtx));
	hdl->running++;
	PTOK(pthread_mutex_unlock(&hdl->mtx));
	PTOK(pthread_attr_init(&attr));
	PTOK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));
	AZ(pthread_create(&thr, &attr, notify_thread, vhdl));
}

static const viov_lease_t mocklease = (viov_lease_t)&mocklease;


//lint -esym(818, cb_priv)
vai_hdl
ObjVAIinit(struct worker *wrk, struct objcore *oc, struct ws *ws,
    vai_notify_cb *cb, void *cb_priv)
{
	struct mockhdl *hdl;

	(void)wrk;
	(void)oc;
	(void)ws;
	AZ(cb);
	AZ(cb_priv);

	ALLOC_OBJ(hdl, MOCKHDL_MAGIC);
	AN(hdl);

	VTAILQ_INIT(&hdl->bufhead);
	PTOK(pthread_mutex_init(&hdl->mtx, NULL));
	PTOK(pthread_cond_init(&hdl->cond, NULL));
	return (hdl);
}

int
ObjVAIlease(struct worker *wrk, vai_hdl vhdl, struct vscarab *scarab)
{
	struct mockhdl *hdl;
	struct viov *vio;
	size_t sz;
	int n, r;

	if (scarab->capacity == scarab->used)
		return (0);
	(void) wrk;
	CAST_OBJ_NOTNULL(hdl, vhdl, MOCKHDL_MAGIC);
	assert(scarab->capacity > scarab->used);

	if (hdl->error_lease == -EAGAIN) {
		notify(vhdl);
		hdl->error_lease = 0;
		hdl->s_lease.again++;
		return (-EAGAIN);
	}
	if (hdl->error_lease == -ENOBUFS) {
		hdl->error_lease = 0;
		hdl->s_lease.nobufs++;
		return (-ENOBUFS);
	}
	if (hdl->error_lease) {
		int error_lease = hdl->error_lease;
		hdl->error_lease = 0;
		return (error_lease);
	}

	n = 1 + VRND_RandomTestable() % (scarab->capacity - scarab->used);
	r = 0;
	while (hdl->leased < hdl->body_len && n--) {
		sz = hdl->body_len - hdl->leased;
		if (sz > 1024)
			sz = (size_t)VRND_RandomTestable() % sz;

		if (hdl->leased == hdl->inject_at) {
			r = -EPIPE;
			break;
		}
		assert(hdl->leased < hdl->inject_at);
		if (hdl->leased + sz > hdl->inject_at)
			sz = hdl->inject_at - hdl->leased;

		vio = VSCARAB_GET(scarab);
		AN(vio);
		vio->lease = mocklease;
		vio->iov.iov_base = hdl->body + hdl->leased;
		vio->iov.iov_len = sz;

		hdl->leased += sz;
		hdl->nleased++;
		r++;
	}
	if ((hdl->mf & MF_EMPTY_VIOV) && ((vio = VSCARAB_GET(scarab)) != NULL)) {
		vio->iov = IOV_NIL;
		vio->lease = mocklease;
		hdl->nleased++;
	}

	if (hdl->mf & MF_LATE_END) {
		if (r == 0 && hdl->leased == hdl->body_len)
			scarab->flags |= VSCARAB_F_END;
	}
	else if (hdl->leased == hdl->body_len)
		scarab->flags |= VSCARAB_F_END;

	return (r);
}

int
ObjVAIbuffer(struct worker *wrk, vai_hdl vhdl, struct vscarab *scarab)
{
	struct mockhdl *hdl;
	struct viov *vio;
	struct mockbuf *b;
	size_t sz;
	const unsigned long addsz = 2752;
	int n, r;

	(void)wrk;
	CAST_OBJ_NOTNULL(hdl, vhdl, MOCKHDL_MAGIC);
	assert(scarab->capacity >= scarab->used);

	if (hdl->error_buffer == -EAGAIN) {
		notify(vhdl);
		hdl->error_buffer = 0;
		hdl->s_buffer.again++;
		return (-EAGAIN);
	}
	if (hdl->error_buffer == -ENOBUFS) {
		hdl->error_buffer = 0;
		hdl->s_buffer.nobufs++;
		return (-ENOBUFS);
	}
	if (hdl->error_buffer) {
		int error_buffer = hdl->error_buffer;
		hdl->error_buffer = 0;
		return (error_buffer);
	}

	n = 1 + VRND_RandomTestable() % scarab->used;
	r = 0;
	VSCARAB_FOREACH(vio, scarab)
		assert(vio->iov.iov_len < UINT_MAX);
	VSCARAB_FOREACH(vio, scarab) {
		if (n-- == 0)
			break;
		sz = vio->iov.iov_len + (unsigned long)VRND_RandomTestable() % addsz;
		if (sz > UINT_MAX)
			sz = UINT_MAX;
		ALLOC_OBJ_EXTRA(b, sz, MOCKBUF_MAGIC);
		AN(b);
		b->sz = sz;
		VTAILQ_INSERT_TAIL(&hdl->bufhead, b, list);

		vio->lease = ptr2lease(b);
		vio->iov.iov_base = b->bytes;
		vio->iov.iov_len = sz;
		r++;
	}

	AN(r);
	return (r);
}

void
ObjVAIreturn(struct worker *wrk, vai_hdl vhdl, struct vscaret *scaret)
{
	struct mockhdl *hdl;
	struct mockbuf *b, *safe;
	viov_lease_t *p;

	(void) wrk;
	CAST_OBJ_NOTNULL(hdl, vhdl, MOCKHDL_MAGIC);
	VSCARET_FOREACH(p, scaret) {
		if (*p == VAI_LEASE_NORET)
			continue;
		if (*p == mocklease) {
			AN(hdl->nleased);
			hdl->nleased--;
			continue;
		}
		VTAILQ_FOREACH_SAFE(b, &hdl->bufhead, list, safe) {
			CHECK_OBJ(b, MOCKBUF_MAGIC);
			if (*p != ptr2lease(b))
				continue;
			VTAILQ_REMOVE(&hdl->bufhead, b, list);
			break;
		}
		if (b == NULL)
			WRONG("returned lease not found");
		free(b);	// NOT FREE_OBJ, sets b = NULL
	}
	VSCARET_INIT(scaret, scaret->capacity);
}

void
ObjVAInotify(struct worker *wrk, vai_hdl vhdl)
{
	struct mockhdl *hdl;

	(void) wrk;
	CAST_OBJ_NOTNULL(hdl, vhdl, MOCKHDL_MAGIC);
	PTOK(pthread_mutex_lock(&hdl->mtx));
	hdl->posted++;
	PTOK(pthread_cond_broadcast(&hdl->cond));
	PTOK(pthread_mutex_unlock(&hdl->mtx));
}

void
ObjVAIfini(struct worker *wrk, vai_hdl *vhdlp)
{
	struct mockhdl *hdl;
	int err;

	(void) wrk;
	TAKE_OBJ_NOTNULL(hdl, vhdlp, MOCKHDL_MAGIC);

	AZ(hdl->nleased);
	assert(VTAILQ_EMPTY(&hdl->bufhead));
	VTAILQ_INIT(&hdl->bufhead);
	while ((err = pthread_mutex_destroy(&hdl->mtx)) != 0)
		assert(err == EBUSY);
	PTOK(pthread_cond_destroy(&hdl->cond));
}

static pthread_mutex_t rndlck = PTHREAD_MUTEX_INITIALIZER;
static void
rndlock(void)
{
	PTOK(pthread_mutex_lock(&rndlck));
}
static void
rndunlock(void)
{
	PTOK(pthread_mutex_unlock(&rndlck));
}

static void
mock_wait(vai_hdl vhdl)
{
	struct mockhdl *hdl;

	CAST_OBJ_NOTNULL(hdl, vhdl, MOCKHDL_MAGIC);
	PTOK(pthread_mutex_lock(&hdl->mtx));
	while (hdl->posted == 0)
		PTOK(pthread_cond_wait(&hdl->cond, &hdl->mtx));
	AN(hdl->posted);
	hdl->posted--;
	PTOK(pthread_mutex_unlock(&hdl->mtx));
}

// return if error
static int
vdpio_mock_cap(const struct vdp *vdp, void *priv, const char *data, size_t datasz, const char *expect, size_t expectsz, unsigned cap, unsigned mf)
{
	VRND_Lock = rndlock;
        VRND_Unlock = rndunlock;

	struct req req[1];
	const unsigned ws_len = 128 << 10;
	void *ws_spc;

	AN(vdp);

	INIT_OBJ(req, REQ_MAGIC);
	ws_spc = malloc(ws_len);
	AN(ws_spc);
	WS_Init(req->ws, "mck", ws_spc, ws_len);

	struct worker wrk[1];
	struct http hp[1];
	struct vdp_ctx vdc[1];
	struct vrt_ctx ctx[1];
	struct vsl_log vsl[1];

	INIT_OBJ(wrk, WORKER_MAGIC);
	INIT_OBJ(hp, HTTP_MAGIC);
	INIT_OBJ(vsl, VSL_LOG_MAGIC);
	intmax_t clen = datasz;
	VDP_Init(vdc, wrk, vsl, req, NULL, &clen);
	vdc->hp = hp;

	INIT_OBJ(ctx, VRT_CTX_MAGIC);
	ctx->ws = req->ws;
	ctx->req = req;

	assert(VDPIO_Push(ctx, vdc, req->ws, vdp, priv) > 0);


	VSCARAB_LOCAL(scarab, cap);
	VSCARET_LOCAL(scaret, cap);

	struct mockhdl *hdl;
	AZ(VDPIO_Init(vdc, NULL, req->ws, NULL, NULL, scaret));
	CAST_OBJ_NOTNULL(hdl, vdc->vai_hdl, MOCKHDL_MAGIC);
	hdl->body = TRUST_ME(data);
	hdl->body_len = datasz;
	hdl->mf = mf;

	if ((mf & MF_ERROR) && datasz >= 4)
		hdl->inject_at = (size_t)VRND_RandomTestable() % (datasz / 4U);
	else
		hdl->inject_at = SIZE_MAX;

	#define MAXITER 10000

	int r;
	int c=0;
	struct viov *v;
	unsigned flags;
	do {
		flags = 0;
		switch (c % 6) {
		// error cases except PIPE (fail)
		case 0:
			hdl->error_buffer = -EAGAIN;
			r = vdpio_pull(vdc, NULL, scarab);
			break;
		case 1:
			hdl->error_lease = -EAGAIN;
			r = vdpio_pull(vdc, NULL, scarab);
			break;
		case 2:
			hdl->error_buffer = -ENOBUFS;
			r = vdpio_pull(vdc, NULL, scarab);
			break;
		case 3:
			hdl->error_lease = -ENOBUFS;
			r = vdpio_pull(vdc, NULL, scarab);
			break;
		// create a partially filled scarab
		case 4:
			AZ(scarab->used);
			assert(scarab->capacity == cap);
			scarab->capacity = 1;
			r = vdpio_pull(vdc, NULL, scarab);
			scarab->capacity = cap;
			continue;
		// good case & potentially final inject
		case 5:
			r = vdpio_pull(vdc, NULL, scarab);
			assert(r <= (int)cap);
			// try to fill up more
			if (r > 0 && scarab->capacity < cap) {
				r = vdpio_pull(vdc, NULL, scarab);
				assert(r <= (int)cap);
			}
			break;
		default:
			WRONG("case");
		}
		if (r == -EAGAIN) {
			mock_wait(hdl);
			continue;
		}
		if (r == -ENOBUFS) {
			ObjVAIreturn(vdc->wrk, vdc->vai_hdl, scaret);
			continue;
		}
		VSCARAB_FOREACH(v, scarab) {
			assert(expectsz >= v->iov.iov_len);
			AZ(memcmp(v->iov.iov_base, expect, v->iov.iov_len));
			expectsz -= v->iov.iov_len;
			expect += v->iov.iov_len;
		}
		flags = scarab->flags;
		vdpio_return_vscarab(vdc, scarab);
		if (r < 0)
			break;
	} while (c++ < MAXITER && (flags & VSCARAB_F_END) == 0); //lint !e845

	#define STRINGIFY(x)  #x
	#define TOSTRING(x)   STRINGIFY(x)
	if (r >= 0 && (flags & VSCARAB_F_END) == 0)
		WRONG("no VSCARAB_F_END seen after " TOSTRING(MAXITER) " iterations");

	if (r >= 0)
		AZ(expectsz);

	// any number of additional calls does not change the result
	for (c = 0; c < 10; c++) {
		r = vdpio_pull(vdc, NULL, scarab);
		if (r >= 0)
			assert(scarab->flags & VSCARAB_F_END);
	}

	if (mf & MF_ERROR)
		assert(r < 0);

	#undef MAXITER
	#undef STRINGIFY
	#undef TOSTRING

	// cheesy wait for pending notification
	while (hdl->running)
		usleep(100);

	vdpio_return_vscarab(vdc, scarab);
	size_t bytes = VDPIO_Close(vdc, NULL, NULL);
	assert(bytes <= datasz);
	if (r > 0)
		assert(bytes == datasz);
	VDPIO_Fini(vdc);

	free(ws_spc);
	if (r > 0)
		r = 0;
	return (r);
}

// return 0 if good
int
vdpio_mock(const struct vdpio_test *t)
{
	unsigned mf, cap;
	int i, seed, r;

	seed = (int)VTIM_real();
	printf("seed: %d\n", seed);

	VRND_SeedTestable(seed);

	for (cap = 1; cap < 9; cap++) {
		const struct vdpio_tc *tc = NULL;
		const char *name;

		for (mf = 0; mf < MF_OK_LIM; mf++) {
			name = "plain";
			r = vdpio_mock_cap(t->vdp, t->vdp_priv, t->data, t->datasz, t->expect, t->expectsz, cap, mf);
			if (r)
				goto fail;

			name = "empty input";
			r = vdpio_mock_cap(t->vdp, t->vdp_priv, "", 0, t->expect_empty, t->expectsz_empty, cap, mf);
			if (r)
				goto fail;

			VFLA_FOREACH(tc, t, tc) {
				name = tc->name;
				r = vdpio_mock_cap(t->vdp, t->vdp_priv, tc->data, tc->datasz, t->expect, t->expectsz, cap, mf);
				if (r != tc->ret)
					goto fail;
			}
		}
		mf = MF_ERROR;
		if (t->no_injection)
			continue;
		name = "error injected";
		for (i = 0; i < 16; i++) {
			r = vdpio_mock_cap(t->vdp, t->vdp_priv, t->data, t->datasz, t->expect, t->expectsz, cap, mf);
			if (r == 0)
				goto fail;
		}
		continue;
	    fail:
		fprintf(stderr, "test failed: vdp=%s tc=%s cap=%u mf=0x%x r=%d\n",
		    t->vdp->name, name, cap, mf, r);
		return (1);
	}
	return (0);
}

#endif


/*
 * generic tests independent of any particular vdpio
 */

#ifdef VDPIO_MAIN_TEST_DRIVER

// exhaustively test all combinations of partially used vscarabs
// and consolidate them
//
// note: using "later" bytes is not actually foreseen as a use case
static void
t_vdpio_consolidate_vscarab(void)
{
	const unsigned cap = 5;
	struct viov *v;
	size_t sz;
	unsigned used;

	// not actually returning anything
	VSCARET_LOCAL(scaret, cap);
	struct vdp_ctx vdc[1];
	INIT_OBJ(vdc, VDP_CTX_MAGIC);
	vdc->scaret = scaret;

	VSCARAB_LOCAL(scarab, cap);
	for (unsigned c = 0; c < 1U<<cap; c++) {
		//lint --e{776,647} truncation
		scarab->used = 0;
		used = 0;
		for (unsigned u = 0; u < cap; u++) {
			assert(u < sizeof(c) * 8);
			sz = c & 1U<<u;
			if (sz || used > 0)
				used++;
			v = VSCARAB_GET(scarab);
			AN(v);
			v->iov.iov_len = sz;
			if (sz == 0)
				v->iov.iov_base = (void *)(uintptr_t)SIZE_MAX;
			else
				v->iov.iov_base = (void *)(uintptr_t)(u + 1);
		}
		assert(scarab->used == cap);
		assert(used <= cap);
		vdpio_consolidate_vscarab(vdc, scarab);
		assert(scarab->used == used);
		VSCARET_INIT(scaret, scaret->capacity);

		if (used > 0)
			AN(scarab->s[0].iov.iov_len);
		VSCARAB_FOREACH(v, scarab) {
			if (v->iov.iov_base == (void *)(uintptr_t)SIZE_MAX) {
				AZ(v->iov.iov_len);
				continue;
			}
			assert(v->iov.iov_len == 1U << ((uintptr_t)v->iov.iov_base - 1));
		}
		if (scarab->used == scarab->capacity)
			continue;
		v = scarab->s + scarab->used;
		scarab->used = scarab->capacity;
		VSCARAB_FOREACH_RESUME(v, scarab) {
			AZ(v->lease);
			AZ(v->iov.iov_base);
			AZ(v->iov.iov_len);
		}

	}
}

// execute the harness on our ObjVAI mock.
// because our interface requires a vdp, we use a null one


static int v_matchproto_(vdpio_init_f)
vdpio_null_init(VRT_CTX, struct vdp_ctx *vdc, void **priv, int capacity)
{
	(void)ctx;
	(void)vdc;
	(void)priv;
	return (capacity);
}

// this is more than just return (vdpio_pull()) only to count bytes
static int v_matchproto_(vdpio_lease_f)
vdpio_null_lease(struct vdp_ctx *vdc, struct vdp_entry *this, struct vscarab *out)
{
	struct viov *v;
	int r;

	this->calls++;
	r = vdpio_pull(vdc, this, out);
	if (r <= 0)
		return (r);
	assert((unsigned)r <= out->used);
	v = &out->s[0];
	v += (out->used - r);
	VSCARAB_FOREACH_RESUME(v, out)
		this->bytes_in += v->iov.iov_len;
	return (r);
}

static const struct vdp VDP_null = {
	.name =		"null",
	.io_init =	vdpio_null_init,
	.io_lease =	vdpio_null_lease,
};

static void
t_harness(const char *fn)
{
	struct vdpio_test t;
	char *data;

	INIT_OBJ(&t, VDPIO_TEST_MAGIC);

	t.vdp = &VDP_null;

	data = VFIL_readfile(NULL, fn, &t.datasz);
	AN(data);
	t.data = data;
	t.expect = t.data;
	t.expectsz = t.datasz;

	AZ(vdpio_mock(&t));

	free(data);
}

int
main(int argc, char *const *argv)
{
	AN(argc);
	t_harness(argv[0]);
	t_vdpio_consolidate_vscarab();
}
#endif
