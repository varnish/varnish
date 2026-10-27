/*-
 * Copyright (c) 2026 Varnish Software AS
 * All rights reserved.
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
 * Disk stevedore
 *
 * Object bodies live in a regular file and are accessed with
 * pread(2)/pwrite(2).  Object metadata (the objcore and all object
 * attributes) live in RAM.
 *
 * Nothing is persistent: the file is just backing store for bodies,
 * and whatever it contains when we open it is ignored and overwritten.
 *
 * The file is fully allocated at startup, so writes do not run out of
 * filesystem space, see sdk_extend().
 */

#include "config.h"

#include <sys/file.h>
#include <sys/syscall.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cache/cache_int.h"
#include "common/heritage.h"

#include "cache/cache_obj.h"
#include "cache/cache_objhead.h"

#include "storage/storage.h"

#include "vfil.h"
#include "vtim.h"
#include "vtree.h"

#include "VSC_disk.h"

/*
 * Allocation granularity.  With 4KB pages, extents never share a page,
 * so a write to a new extent does not make the kernel read the rest of
 * a page it has evicted, see sdk_zero().
 */
#define SDK_GRAN		4096
#define SDK_EXT_MIN		(64 * 1024)	/* first extent */
#define SDK_EXT_MAX		(16 * 1024 * 1024)
#define SDK_EXT_ACCEPT		(4 * 1024)	/* smallest acceptable */
#define SDK_WRBUF		(64 * 1024)	/* fetch staging buffer */
#define SDK_RDBUF		(64 * 1024)	/* delivery buffer */



static struct VSC_lck *lck_sdk;

/*--------------------------------------------------------------------
 * Free space, kept in two trees: by offset for coalescing and by
 * length (then offset) for best fit allocation.
 */

struct sdk_free {
	unsigned		magic;
#define SDK_FREE_MAGIC		0x5b1f0a7d
	uint64_t		off;
	uint64_t		len;
	VRBT_ENTRY(sdk_free)	e_off;
	VRBT_ENTRY(sdk_free)	e_len;
};

VRBT_HEAD(sdk_free_off, sdk_free);
VRBT_HEAD(sdk_free_len, sdk_free);

static inline int
sdk_free_off_cmp(const struct sdk_free *a, const struct sdk_free *b)
{
	if (a->off < b->off)
		return (-1);
	return (a->off > b->off);
}

static inline int
sdk_free_len_cmp(const struct sdk_free *a, const struct sdk_free *b)
{
	if (a->len != b->len)
		return (a->len < b->len ? -1 : 1);
	return (sdk_free_off_cmp(a, b));
}

VRBT_GENERATE_STATIC(sdk_free_off, sdk_free, e_off, sdk_free_off_cmp)
VRBT_GENERATE_STATIC(sdk_free_len, sdk_free, e_len, sdk_free_len_cmp)

/*--------------------------------------------------------------------*/

struct sdk_ext {
	uint64_t		off;
	uint64_t		len;	/* bytes used */
	uint64_t		space;	/* bytes allocated */
};

struct sdk_sc {
	unsigned		magic;
#define SDK_SC_MAGIC		0x2e0c7d51
	struct lock		mtx;
	struct VSC_disk		*stats;
	const struct stevedore	*stv;

	const char		*filename;
	int			fd;
	uint64_t		mediasize;
	uint64_t		data_end;

	unsigned		zero;

	struct sdk_free_off	free_off;
	struct sdk_free_len	free_len;

};

struct sdk_obj {
	unsigned		magic;
#define SDK_OBJ_MAGIC		0x6d1b3f2a
	struct sdk_sc		*sc;
	struct objcore		*oc;

	/* Fixed size attributes */
#define OBJ_FIXATTR(U, l, s)			\
	uint8_t			fa_##l[s];
#include "tbl/obj_attr.h"

	/* Variable size attributes */
#define OBJ_VARATTR(U, l)			\
	uint8_t			*va_##l;	\
	unsigned		va_##l##_len;
#include "tbl/obj_attr.h"

	/* Auxiliary attributes */
#define OBJ_AUXATTR(U, l)			\
	uint8_t			*aa_##l;	\
	unsigned		aa_##l##_len;
#include "tbl/obj_attr.h"

	/* Body, protected by boc->mtx while there is a boc */
	struct sdk_ext		*ext;
	unsigned		n_ext;
	unsigned		l_ext;
	uint64_t		len;
};

/* Fetch state, hangs off boc->stevedore_priv */
struct sdk_fetch {
	unsigned		magic;
#define SDK_FETCH_MAGIC		0x0f3a91c4
	uint8_t			*buf;
	size_t			pos;
	uint64_t		want;	/* last extent size requested */
};

/*--------------------------------------------------------------------
 * I/O helpers
 */

static int
sdk_pwrite(const struct sdk_sc *sc, const void *ptr, size_t len, uint64_t off)
{
	const uint8_t *p = ptr;
	ssize_t i;

	while (len > 0) {
		i = pwrite(sc->fd, p, len, (off_t)off);
		if (i < 0 && errno == EINTR)
			continue;
		if (i == 0)
			errno = EIO;
		if (i <= 0)
			return (-1);
		p += i;
		off += i;
		len -= i;
	}
	return (0);
}

static int
sdk_pread(const struct sdk_sc *sc, void *ptr, size_t len, uint64_t off)
{
	uint8_t *p = ptr;
	ssize_t i;

	while (len > 0) {
		i = pread(sc->fd, p, len, (off_t)off);
		if (i < 0 && errno == EINTR)
			continue;
		if (i == 0)
			errno = EIO;
		if (i <= 0)
			return (-1);
		p += i;
		off += i;
		len -= i;
	}
	return (0);
}

static inline uint64_t
sdk_roundup(uint64_t x)
{
	return ((x + SDK_GRAN - 1) & ~((uint64_t)SDK_GRAN - 1));
}

/*--------------------------------------------------------------------
 * Allocator, all called with sc->mtx held
 */

static void
sdk_free_insert(struct sdk_sc *sc, uint64_t off, uint64_t len)
{
	struct sdk_free *f, *prev, *next, key;

	Lck_AssertHeld(&sc->mtx);
	assert(len > 0);
	assert(off % SDK_GRAN == 0);
	assert(len % SDK_GRAN == 0);
	assert(off + len <= sc->data_end);

	key.off = off;
	next = VRBT_NFIND(sdk_free_off, &sc->free_off, &key);
	if (next != NULL)
		prev = VRBT_PREV(sdk_free_off, &sc->free_off, next);
	else
		prev = VRBT_MAX(sdk_free_off, &sc->free_off);

	if (prev != NULL)
		assert(prev->off + prev->len <= off);
	if (next != NULL)
		assert(off + len <= next->off);

	if (prev != NULL && prev->off + prev->len == off) {
		f = prev;
		VRBT_REMOVE(sdk_free_len, &sc->free_len, f);
		f->len += len;
	} else {
		ALLOC_OBJ(f, SDK_FREE_MAGIC);
		AN(f);
		f->off = off;
		f->len = len;
		AZ(VRBT_INSERT(sdk_free_off, &sc->free_off, f));
		sc->stats->g_free_ext++;
	}

	if (next != NULL && f->off + f->len == next->off) {
		VRBT_REMOVE(sdk_free_len, &sc->free_len, next);
		VRBT_REMOVE(sdk_free_off, &sc->free_off, next);
		f->len += next->len;
		FREE_OBJ(next);
		sc->stats->g_free_ext--;
	}

	AZ(VRBT_INSERT(sdk_free_len, &sc->free_len, f));
}

/*
 * Allocate want bytes, or failing that the largest free extent if it
 * is at least min bytes.
 */
static int
sdk_alloc_locked(struct sdk_sc *sc, uint64_t want, uint64_t min,
    struct sdk_ext *e)
{
	struct sdk_free *f, key;

	Lck_AssertHeld(&sc->mtx);
	want = sdk_roundup(want);
	min = sdk_roundup(min);
	assert(min <= want);

	key.len = want;
	key.off = 0;
	f = VRBT_NFIND(sdk_free_len, &sc->free_len, &key);
	if (f == NULL) {
		f = VRBT_MAX(sdk_free_len, &sc->free_len);
		if (f == NULL || f->len < min)
			return (-1);
		want = f->len;
	}
	CHECK_OBJ_NOTNULL(f, SDK_FREE_MAGIC);
	assert(f->len >= want);

	VRBT_REMOVE(sdk_free_len, &sc->free_len, f);
	e->off = f->off;
	e->len = 0;
	e->space = want;
	if (f->len == want) {
		VRBT_REMOVE(sdk_free_off, &sc->free_off, f);
		FREE_OBJ(f);
		sc->stats->g_free_ext--;
	} else {
		/* Shrinking from the front keeps the offset order */
		f->off += want;
		f->len -= want;
		AZ(VRBT_INSERT(sdk_free_len, &sc->free_len, f));
	}
	return (0);
}

/*
 * Our writes rarely end on a page boundary.  If the rest of the page was
 * written before, and has since been evicted from the page cache, the
 * kernel must read it back before it can take the write, and the fetch
 * waits for that read while holding the boc mtx.  Recycled space in a
 * storage larger than RAM is mostly evicted, so we tell the filesystem
 * that a new extent holds zeros, which needs no reading.
 */
static void
sdk_zero_init(struct sdk_sc *sc)
{
#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_ZERO_RANGE)

	/* Probe on the start of the file, which holds nothing yet */
	sc->zero = !fallocate(sc->fd,
	    FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE, 0, SDK_GRAN);
#else
	sc->zero = 0;
#endif
}

#ifdef SYS_cachestat
/* From <linux/mman.h>, which does not mix well with <sys/mman.h> */
struct sdk_cachestat_range {
	uint64_t		off;
	uint64_t		len;
};

struct sdk_cachestat {
	uint64_t		nr_cache;
	uint64_t		nr_dirty;
	uint64_t		nr_writeback;
	uint64_t		nr_evicted;
	uint64_t		nr_recently_evicted;
};
#endif

static void
sdk_zero(const struct sdk_sc *sc, const struct sdk_ext *e)
{
#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_ZERO_RANGE)
#  ifdef SYS_cachestat
	struct sdk_cachestat_range cr;
	struct sdk_cachestat cs;
#  endif

	if (!sc->zero)
		return;
#  ifdef SYS_cachestat
	/*
	 * Recently freed space may still be in the page cache, where
	 * writes need no reading, and zeroing would have to write back
	 * whatever is dirty first.
	 */
	cr.off = e->off;
	cr.len = e->space;
	if (!syscall(SYS_cachestat, sc->fd, &cr, &cs, 0) &&
	    cs.nr_cache * (uint64_t)getpagesize() >= e->space)
		return;
#  endif
	(void)fallocate(sc->fd, FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
	    (off_t)e->off, (off_t)e->space);
#else
	(void)sc;
	(void)e;
#endif
}

static int
sdk_alloc(struct sdk_sc *sc, uint64_t want, uint64_t min, struct sdk_ext *e)
{
	int r;

	Lck_Lock(&sc->mtx);
	sc->stats->c_req++;
	r = sdk_alloc_locked(sc, want, min, e);
	if (r == 0) {
		sc->stats->g_alloc++;
		sc->stats->c_bytes += e->space;
		sc->stats->g_bytes += e->space;
		sc->stats->g_space -= e->space;
	} else
		sc->stats->c_fail++;
	Lck_Unlock(&sc->mtx);
	if (r == 0)
		sdk_zero(sc, e);
	return (r);
}

static void
sdk_free_ext_locked(struct sdk_sc *sc, uint64_t off, uint64_t space)
{

	Lck_AssertHeld(&sc->mtx);
	if (space == 0)
		return;
	sdk_free_insert(sc, off, space);
	sc->stats->c_freed += space;
	sc->stats->g_bytes -= space;
	sc->stats->g_space += space;
}

/*--------------------------------------------------------------------
 * Objects
 */

static struct sdk_obj *
sdk_getobj(const struct objcore *oc)
{
	struct sdk_obj *o;

	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CAST_OBJ_NOTNULL(o, oc->stobj->priv, SDK_OBJ_MAGIC);
	return (o);
}

static void
sdk_obj_free_attrs(struct sdk_obj *o, int aux_only)
{

#define OBJ_AUXATTR(U, l)			\
	free(o->aa_##l);			\
	o->aa_##l = NULL;			\
	o->aa_##l##_len = 0;
#include "tbl/obj_attr.h"

	if (aux_only)
		return;

#define OBJ_VARATTR(U, l)			\
	free(o->va_##l);			\
	o->va_##l = NULL;			\
	o->va_##l##_len = 0;
#include "tbl/obj_attr.h"
}

/* Release the body extents */
static void
sdk_obj_release(struct sdk_sc *sc, struct sdk_obj *o)
{
	unsigned u;

	Lck_Lock(&sc->mtx);
	for (u = 0; u < o->n_ext; u++) {
		sdk_free_ext_locked(sc, o->ext[u].off, o->ext[u].space);
		if (o->ext[u].space > 0)
			sc->stats->g_alloc--;
	}
	Lck_Unlock(&sc->mtx);
	free(o->ext);
	o->ext = NULL;
	o->n_ext = o->l_ext = 0;
	o->len = 0;
}

static void
sdk_fetch_fini(struct boc *boc)
{
	struct sdk_fetch *fs;

	CHECK_OBJ_NOTNULL(boc, BOC_MAGIC);
	if (boc->stevedore_priv == NULL)
		return;
	TAKE_OBJ_NOTNULL(fs, &boc->stevedore_priv, SDK_FETCH_MAGIC);
	free(fs->buf);
	FREE_OBJ(fs);
}

static int v_matchproto_(storage_allocobj_f)
sdk_allocobj(struct worker *wrk, const struct stevedore *stv,
    struct objcore *oc, unsigned wsl)
{
	struct sdk_obj *o;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	(void)wsl;

	ALLOC_OBJ(o, SDK_OBJ_MAGIC);
	if (o == NULL)
		return (0);
	CAST_OBJ_NOTNULL(o->sc, stv->priv, SDK_SC_MAGIC);
	o->oc = oc;
	oc->stobj->stevedore = stv;
	oc->stobj->priv = o;
	oc->stobj->priv2 = 0;
	return (1);
}

static void v_matchproto_(objfree_f)
sdk_objfree(struct worker *wrk, struct objcore *oc)
{
	const struct stevedore *stv;
	struct sdk_obj *o;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	stv = oc->stobj->stevedore;
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	o = sdk_getobj(oc);

	sdk_obj_release(o->sc, o);
	sdk_obj_free_attrs(o, 0);

	if (oc->boc != NULL)
		sdk_fetch_fini(oc->boc);
	else if (stv->lru != NULL)
		LRU_Remove(oc);

	FREE_OBJ(o);
	memset(oc->stobj, 0, sizeof oc->stobj);
	wrk->stats->n_object--;
}

static void v_matchproto_(objslim_f)
sdk_slim(struct worker *wrk, struct objcore *oc)
{
	struct sdk_obj *o;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	o = sdk_getobj(oc);
	sdk_obj_release(o->sc, o);
	sdk_obj_free_attrs(o, 1);
}

/*--------------------------------------------------------------------
 * Fetch: ObjGetSpace() hands out a region of a RAM staging buffer, and
 * ObjExtend() writes what was filled in straight through to the extent
 * before the bytes become visible to streaming readers.
 */

static int v_matchproto_(objgetspace_f)
sdk_getspace(struct worker *wrk, struct objcore *oc, ssize_t *sz,
    uint8_t **ptr)
{
	const struct stevedore *stv;
	struct sdk_fetch *fs;
	struct sdk_obj *o;
	struct sdk_ext *e, ne;
	uint64_t want, min;
	unsigned n_ext;
	size_t l;
	int cancelled, known;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(oc->boc, BOC_MAGIC);
	AN(sz);
	AN(ptr);
	stv = oc->stobj->stevedore;
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	o = sdk_getobj(oc);

	/* A size hint is what remains of a known length */
	known = *sz > 0;
	if (*sz == 0)
		*sz = cache_param->fetch_chunksize;
	assert(*sz > 0);
	if (oc->boc->transit_buffer > 0)
		*sz = vmin_t(ssize_t, *sz, oc->boc->transit_buffer);

	if (oc->boc->stevedore_priv == NULL) {
		ALLOC_OBJ(fs, SDK_FETCH_MAGIC);
		if (fs == NULL)
			return (0);
		fs->buf = malloc(SDK_WRBUF);
		if (fs->buf == NULL) {
			FREE_OBJ(fs);
			return (0);
		}
		oc->boc->stevedore_priv = fs;
	}
	CAST_OBJ_NOTNULL(fs, oc->boc->stevedore_priv, SDK_FETCH_MAGIC);

	Lck_Lock(&oc->boc->mtx);
	n_ext = o->n_ext;
	e = n_ext > 0 ? &o->ext[n_ext - 1] : NULL;
	if (e == NULL || e->len == e->space) {
		/*
		 * Allocating more than we need for a small object leaves
		 * a hole when it is trimmed, which concurrent fetches can
		 * keep from coalescing.
		 *
		 * Grow from what we last asked for, not from what we got,
		 * so a fragment does not restart the growth.
		 */
		if (known)
			want = *sz;
		else if (fs->want == 0)
			want = vmax_t(uint64_t, *sz, SDK_EXT_MIN);
		else
			want = vmax_t(uint64_t, *sz, fs->want * 2);
		want = vmin_t(uint64_t, want, SDK_EXT_MAX);
		if (oc->boc->transit_buffer > 0)
			want = vmin_t(uint64_t, want,
			    oc->boc->transit_buffer);
		fs->want = want;
		min = vmin_t(uint64_t, want, SDK_EXT_ACCEPT);
		Lck_Unlock(&oc->boc->mtx);

		while (sdk_alloc(o->sc, want, min, &ne)) {
			if (stv->lru != NULL && LRU_NukeOne(wrk, stv->lru))
				continue;
			if (oc->boc->transit_buffer == 0 || n_ext == 0)
				return (0);
			/* The consumer can return extents while we wait. */
			Lck_Lock(&oc->boc->mtx);
			while (o->n_ext == n_ext &&
			    !(oc->flags & OC_F_CANCEL))
				(void)Lck_CondWait(&oc->boc->cond,
				    &oc->boc->mtx);
			n_ext = o->n_ext;
			cancelled = oc->flags & OC_F_CANCEL;
			Lck_Unlock(&oc->boc->mtx);
			if (cancelled)
				return (0);
		}

		Lck_Lock(&oc->boc->mtx);
		if (o->n_ext == o->l_ext) {
			o->l_ext = o->l_ext ? o->l_ext * 2 : 4;
			o->ext = realloc(o->ext, o->l_ext * sizeof *o->ext);
			AN(o->ext);
		}
		o->ext[o->n_ext++] = ne;
		e = &o->ext[o->n_ext - 1];
	}
	assert(e->len < e->space);

	/* A tiny remainder is not worth a VFP round trip and a write */
	if (SDK_WRBUF - fs->pos < SDK_GRAN)
		fs->pos = 0;
	l = vmin_t(size_t, SDK_WRBUF - fs->pos, e->space - e->len);
	if (oc->boc->transit_buffer > 0)
		l = vmin_t(size_t, l, *sz);
	Lck_Unlock(&oc->boc->mtx);
	assert(l > 0);
	*sz = (ssize_t)l;
	*ptr = fs->buf + fs->pos;
	return (1);
}

static void v_matchproto_(objextend_f)
sdk_extend(struct worker *wrk, struct objcore *oc, ssize_t l)
{
	struct sdk_fetch *fs;
	struct sdk_obj *o;
	struct sdk_ext *e;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(oc->boc, BOC_MAGIC);
	assert(l > 0);
	o = sdk_getobj(oc);
	CAST_OBJ_NOTNULL(fs, oc->boc->stevedore_priv, SDK_FETCH_MAGIC);

	AN(o->n_ext);
	e = &o->ext[o->n_ext - 1];
	assert(e->len + l <= e->space);
	assert(fs->pos + l <= SDK_WRBUF);

	/*
	 * XXX: This is called with the boc mtx held.  The write normally
	 * only hits the page cache, but under writeback pressure this will
	 * hold up streaming readers of this object.
	 *
	 * The void extend interface cannot report an I/O failure to the
	 * fetch. Panic rather than publish unwritten bytes to readers.
	 */
	if (sdk_pwrite(o->sc, fs->buf + fs->pos, l, e->off + e->len))
		WRONG("disk stevedore write error");
	fs->pos += l;
	e->len += l;
	o->len += l;
}

static void v_matchproto_(objtrimstore_f)
sdk_trimstore(struct worker *wrk, struct objcore *oc)
{
	struct sdk_obj *o;
	struct sdk_ext *e;
	uint64_t space;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(oc->boc, BOC_MAGIC);
	o = sdk_getobj(oc);

	sdk_fetch_fini(oc->boc);

	Lck_Lock(&oc->boc->mtx);
	if (o->n_ext == 0) {
		Lck_Unlock(&oc->boc->mtx);
		return;
	}
	e = &o->ext[o->n_ext - 1];
	space = sdk_roundup(e->len);
	if (space == e->space) {
		Lck_Unlock(&oc->boc->mtx);
		return;
	}

	Lck_Lock(&o->sc->mtx);
	sdk_free_ext_locked(o->sc, e->off + space, e->space - space);
	if (space == 0)
		o->sc->stats->g_alloc--;
	Lck_Unlock(&o->sc->mtx);

	e->space = space;
	if (space == 0)
		o->n_ext--;
	Lck_Unlock(&oc->boc->mtx);
}

static void v_matchproto_(objbocdone_f)
sdk_bocdone(struct worker *wrk, struct objcore *oc, struct boc *boc)
{
	const struct stevedore *stv;
	vtim_real t;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(boc, BOC_MAGIC);
	stv = oc->stobj->stevedore;
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);

	sdk_fetch_fini(boc);

	if (stv->lru == NULL)
		return;
	if (isnan(wrk->lastused))
		wrk->lastused = VTIM_real();
	t = wrk->lastused;	// approx timestamp is OK
	LRU_Add(oc, t);
}

/*--------------------------------------------------------------------
 * Delivery
 *
 * We read into a buffer which is reused, so every chunk handed to the
 * iterator function must be flushed.
 */

static void
sdk_iterator_free_ext(struct sdk_obj *o, struct boc *boc, unsigned ei)
{
	struct sdk_ext *e;

	if (boc != NULL)
		Lck_Lock(&boc->mtx);
	assert(ei < o->n_ext);
	e = &o->ext[ei];
	Lck_Lock(&o->sc->mtx);
	sdk_free_ext_locked(o->sc, e->off, e->space);
	o->sc->stats->g_alloc--;
	Lck_Unlock(&o->sc->mtx);
	memmove(e, e + 1, (o->n_ext - ei - 1) * sizeof *e);
	o->n_ext--;
	if (boc != NULL) {
		/* The fetch may share the condvar with other waiters */
		PTOK(pthread_cond_broadcast(&boc->cond));
		Lck_Unlock(&boc->mtx);
	}
}

static int v_matchproto_(objiterator_f)
sdk_iterator(struct worker *wrk, struct objcore *oc,
    void *priv, objiterate_f *func, int final)
{
	enum boc_state_e state = BOS_FINISHED;
	struct sdk_obj *o;
	struct sdk_ext e;
	struct boc *boc;
	uint64_t avail, done = 0, epos = 0;
	unsigned ei = 0, u = 0;
	uint8_t *buf;
	size_t bufsz, l;
	int r = 0, r2;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	AN(func);
	o = sdk_getobj(oc);

	boc = HSH_RefBoc(oc);
	if (boc == NULL) {
		avail = o->len;
		bufsz = vmin_t(size_t, avail, SDK_RDBUF);
	} else {
		avail = 0;
		bufsz = SDK_RDBUF;
	}

	buf = NULL;
	if (bufsz > 0) {
		buf = malloc(bufsz);
		if (buf == NULL)
			r = -1;
	}

	while (r == 0) {
		if (boc != NULL) {
			avail = ObjWaitExtend(wrk, oc, done, &state);
			if (state == BOS_FAILED) {
				r = -1;
				break;
			}
		}
		while (r == 0 && done < avail) {
			if (boc != NULL)
				Lck_Lock(&boc->mtx);
			assert(ei < o->n_ext);
			e = o->ext[ei];
			if (boc != NULL)
				Lck_Unlock(&boc->mtx);
			assert(epos <= e.len);
			if (epos == e.len) {
				ei++;
				epos = 0;
				continue;
			}
			l = vmin_t(size_t, e.len - epos, avail - done);
			l = vmin_t(size_t, l, bufsz);
			AN(buf);
			if (sdk_pread(o->sc, buf, l, e.off + epos)) {
				VSLb(wrk->vsl, SLT_Error,
				    "disk stevedore read error: %s",
				    VAS_errtxt(errno));
				r = -1;
				break;
			}
			epos += l;
			done += l;
			u = OBJ_ITER_FLUSH;
			if (done == avail && state == BOS_FINISHED)
				u |= OBJ_ITER_END;
			r = func(priv, u, buf, l);
			if (final && r == 0 && (epos == e.space ||
			    (state == BOS_FINISHED && epos == e.len))) {
				sdk_iterator_free_ext(o, boc, ei);
				epos = 0;
			}
		}
		if (state == BOS_FINISHED && done == avail)
			break;
	}

	if (!(u & OBJ_ITER_END)) {
		r2 = func(priv, OBJ_ITER_END, NULL, 0);
		if (r == 0)
			r = r2;
	}

	free(buf);
	if (boc != NULL)
		HSH_DerefBoc(wrk, oc);
	return (r);
}

/*--------------------------------------------------------------------
 * Attributes, all in RAM
 */

static const void * v_matchproto_(objgetattr_f)
sdk_getattr(struct worker *wrk, struct objcore *oc, enum obj_attr attr,
   ssize_t *len)
{
	struct sdk_obj *o;
	ssize_t dummy;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	if (len == NULL)
		len = &dummy;
	o = sdk_getobj(oc);

	switch (attr) {
#define OBJ_FIXATTR(U, l, s)						\
	case OA_##U:							\
		*len = sizeof o->fa_##l;				\
		return (o->fa_##l);
#include "tbl/obj_attr.h"

#define OBJ_VARATTR(U, l)						\
	case OA_##U:							\
		if (o->va_##l == NULL)					\
			return (NULL);					\
		*len = o->va_##l##_len;					\
		return (o->va_##l);
#include "tbl/obj_attr.h"

#define OBJ_AUXATTR(U, l)						\
	case OA_##U:							\
		if (o->aa_##l == NULL)					\
			return (NULL);					\
		*len = o->aa_##l##_len;					\
		return (o->aa_##l);
#include "tbl/obj_attr.h"

	default:
		break;
	}
	WRONG("Unsupported OBJ_ATTR");
}

static void * v_matchproto_(objsetattr_f)
sdk_setattr(struct worker *wrk, struct objcore *oc, enum obj_attr attr,
    ssize_t len, const void *ptr)
{
	struct sdk_obj *o;
	void *retval = NULL;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	o = sdk_getobj(oc);

	switch (attr) {
#define OBJ_FIXATTR(U, l, s)						\
	case OA_##U:							\
		assert(len == sizeof o->fa_##l);			\
		retval = o->fa_##l;					\
		break;
#include "tbl/obj_attr.h"

#define OBJ_SETATTR(x)							\
		if (x##_len > 0) {					\
			AN(x);						\
			assert(len == x##_len);				\
			retval = x;					\
		} else if (len > 0) {					\
			assert(len <= UINT_MAX);			\
			x = malloc(len);				\
			if (x == NULL)					\
				break;					\
			x##_len = len;					\
			retval = x;					\
		}							\
		break;

#define OBJ_VARATTR(U, l)						\
	case OA_##U:							\
		OBJ_SETATTR(o->va_##l)
#include "tbl/obj_attr.h"

#define OBJ_AUXATTR(U, l)						\
	case OA_##U:							\
		OBJ_SETATTR(o->aa_##l)
#include "tbl/obj_attr.h"

#undef OBJ_SETATTR

	default:
		WRONG("Unsupported OBJ_ATTR");
		break;
	}

	if (retval != NULL && ptr != NULL)
		memcpy(retval, ptr, len);
	return (retval);
}

static const struct obj_methods sdk_methods = {
	.objfree	= sdk_objfree,
	.objiterator	= sdk_iterator,
	.objgetspace	= sdk_getspace,
	.objextend	= sdk_extend,
	.objtrimstore	= sdk_trimstore,
	.objbocdone	= sdk_bocdone,
	.objslim	= sdk_slim,
	.objgetattr	= sdk_getattr,
	.objsetattr	= sdk_setattr,
	.objtouch	= LRU_Touch,
};

static void v_matchproto_(storage_panic_f)
sdk_panic(struct vsb *vsb, const struct objcore *oc)
{
	const struct sdk_obj *o;
	unsigned u;

	o = oc->stobj->priv;
	if (PAN_dump_struct(vsb, o, SDK_OBJ_MAGIC, "disk"))
		return;
	VSB_printf(vsb, "len = %ju, n_ext = %u,\n",
	    (uintmax_t)o->len, o->n_ext);
	for (u = 0; u < o->n_ext && u < 8; u++)
		VSB_printf(vsb, "ext = {off=%ju, len=%ju, space=%ju},\n",
		    (uintmax_t)o->ext[u].off, (uintmax_t)o->ext[u].len,
		    (uintmax_t)o->ext[u].space);
	VSB_indent(vsb, -2);
	VSB_cat(vsb, "},\n");
}

/*--------------------------------------------------------------------
 * Buffers, for gzip and h2 request bodies when we are the Transient
 * storage.  They are short lived and never reach the file.
 */

static void * v_matchproto_(storage_allocbuf_f)
sdk_allocbuf(struct worker *wrk, const struct stevedore *stv, size_t size,
    uintptr_t *ppriv)
{
	void *p;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	AN(ppriv);

	p = malloc(size);
	if (p == NULL)
		return (NULL);
	*ppriv = (uintptr_t)p;
	return (p);
}

static void v_matchproto_(storage_freebuf_f)
sdk_freebuf(struct worker *wrk, const struct stevedore *stv, uintptr_t priv)
{

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	free((void *)priv);
}

/*--------------------------------------------------------------------
 * Open the storage in the cache process
 */

static void v_matchproto_(storage_open_f)
sdk_open(struct stevedore *stv)
{
	struct sdk_sc *sc;

	ASSERT_CLI();
	if (lck_sdk == NULL)
		lck_sdk = Lck_CreateClass(NULL, "sdk");
	CAST_OBJ_NOTNULL(sc, stv->priv, SDK_SC_MAGIC);
	sc->stv = stv;
	stv->lru = LRU_Alloc();
	sc->stats = VSC_disk_New(NULL, NULL, stv->ident);
	Lck_New(&sc->mtx, lck_sdk);
	VRBT_INIT(&sc->free_off);
	VRBT_INIT(&sc->free_len);
	Lck_Lock(&sc->mtx);
	sdk_free_insert(sc, 0, sc->data_end);
	Lck_Unlock(&sc->mtx);
	sc->stats->g_space = sc->data_end;
	sdk_zero_init(sc);
}

/*--------------------------------------------------------------------
 * Configure the storage before entering the worker jail
 */

static void v_matchproto_(storage_init_f)
sdk_init(struct stevedore *parent, int ac, char * const *av)
{
	const char *size = NULL;
	struct sdk_sc *sc;
	unsigned gran = SDK_GRAN;
	int r;

	AZ(av[ac]);
	if (ac > 2)
		ARGV_ERR("(-sdisk) too many arguments\n");
	if (ac < 1 || *av[0] == '\0')
		ARGV_ERR("(-sdisk) path is mandatory\n");
	if (ac > 1 && *av[1] != '\0')
		size = av[1];

	ALLOC_OBJ(sc, SDK_SC_MAGIC);
	AN(sc);
	sc->fd = -1;
	(void)STV_GetFile(av[0], &sc->fd, &sc->filename, "-sdisk");
	do {
		r = flock(sc->fd, LOCK_EX | LOCK_NB);
	} while (r && errno == EINTR);
	if (r)
		ARGV_ERR("(-sdisk) %s: cannot lock storage file: %s\n",
		    sc->filename, VAS_errtxt(errno));
	MCH_Fd_Inherit(sc->fd, "storage_disk");
	sc->mediasize = STV_FileSize(sc->fd, size, &gran, "-sdisk");
	if (sc->mediasize < SDK_EXT_MAX)
		ARGV_ERR("(-sdisk) size too small\n");
	/*
	 * Insist on allocating the whole file now: a sparse file would
	 * turn a full filesystem into a write error in sdk_extend().
	 */
	if (VFIL_allocate(sc->fd, (off_t)sc->mediasize, 1))
		ARGV_ERR("(-sdisk) allocation error: %s\n",
		    VAS_errtxt(errno));
	sc->data_end = sc->mediasize & ~((uint64_t)SDK_GRAN - 1);
	parent->priv = sc;
}

const struct stevedore sdk_stevedore = {
	.magic		=	STEVEDORE_MAGIC,
	.name		=	"disk",
	.init		=	sdk_init,
	.open		=	sdk_open,
	.allocobj	=	sdk_allocobj,
	.allocbuf	=	sdk_allocbuf,
	.freebuf	=	sdk_freebuf,
	.panic		=	sdk_panic,
	.methods	=	&sdk_methods,
};
