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
 * Object bodies live in a file (or block device) and are accessed with
 * pread(2)/pwrite(2).  Object metadata (the objcore and all object
 * attributes) live in RAM.
 *
 * The content survives an orderly restart of the cache process: on
 * close we write an index of all objects into free space in the file,
 * sync it, and mark the header clean.  On open we clear the clean mark
 * (synchronously) before anything else is written, and only load the
 * index if the mark was set.
 *
 * This stevedore is deliberately not crash-safe: if the cache process
 * dies for any other reason than an orderly shutdown, all content is
 * forfeited on the next start.
 *
 * File layout:
 *
 *	[0, SDK_HDR_SIZE)		header
 *	[SDK_HDR_SIZE, mediasize)	extents, SDK_GRAN aligned
 *
 * The index is only valid while the header is marked clean, and is
 * written as a byte stream into a list of extents recorded in the
 * header:
 *
 *	uint32_t	ban list length
 *	uint8_t[]	ban list (as exported by cache_ban.c)
 *	records		one per object, see sdk_save_obj()
 *	uint32_t	SDK_REC_END
 */

#include "config.h"

#include <sys/file.h>

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
#include "vsha256.h"
#include "vtim.h"
#include "vtree.h"

#include "VSC_disk.h"

#define SDK_HDR_SIZE		4096
#define SDK_GRAN		512		/* allocation granularity */
#define SDK_EXT_MIN		(64 * 1024)	/* first extent */
#define SDK_EXT_MAX		(16 * 1024 * 1024)
#define SDK_EXT_ACCEPT		(4 * 1024)	/* smallest acceptable */
#define SDK_WRBUF		(64 * 1024)	/* fetch staging buffer */
#define SDK_RDBUF		(64 * 1024)	/* delivery buffer */
#define SDK_IOBUF		(1024 * 1024)	/* index io buffer */
#define SDK_IDX_EXT		128		/* index extents in header */

#define SDK_HDR_SIGNATURE	"Varnish Disk 1\n"
#define SDK_BYTEORDER		0x01020304U
#define SDK_VERSION		1U
#define SDK_REC_SIGNATURE	0x5344524bU	/* "SDRK" */
#define SDK_REC_END		0x53444e44U	/* "SDND" */

/* sanity limits when parsing the index */
#define SDK_MAX_EXT		(1U << 20)
#define SDK_MAX_ATTR		(1U << 30)

static struct VSC_lck *lck_sdk;

/*--------------------------------------------------------------------
 * On-disk header
 */

struct sdk_hdr_ext {
	uint64_t		off;
	uint64_t		len;
};

struct sdk_hdr {
	char			magic[16];
	uint32_t		byteorder;
	uint32_t		version;
	uint32_t		hdrsize;
	uint32_t		clean;
	uint64_t		mediasize;
	uint64_t		gran;
	uint64_t		idx_len;
	uint8_t			idx_sha[VSHA256_LEN];
	uint32_t		n_idx_ext;
	uint32_t		pad;
	struct sdk_hdr_ext	idx_ext[SDK_IDX_EXT];
	/* Must be last */
	uint8_t			hdr_sha[VSHA256_LEN];
};

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

VTAILQ_HEAD(sdk_objhead, sdk_obj);

struct sdk_sc {
	unsigned		magic;
#define SDK_SC_MAGIC		0x2e0c7d51
	struct lock		mtx;
	struct VSC_disk		*stats;
	const struct stevedore	*stv;

	const char		*filename;
	int			fd;
	uint64_t		mediasize;
	uint64_t		data_start;
	uint64_t		data_end;

	unsigned		closed;

	struct sdk_free_off	free_off;
	struct sdk_free_len	free_len;

	/* completed objects, candidates for the index */
	struct sdk_objhead	objs;

	/* latest ban list export */
	uint8_t			*bans;
	unsigned		bans_len;
};

struct sdk_obj {
	unsigned		magic;
#define SDK_OBJ_MAGIC		0x6d1b3f2a
	unsigned		flags;
#define SDK_OF_LISTED		(1U << 0)
#define SDK_OF_LOADED		(1U << 1)
#define SDK_OF_SAVE		(1U << 2)
	struct sdk_sc		*sc;
	struct objcore		*oc;
	VTAILQ_ENTRY(sdk_obj)	list;

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

	/* Used only when loading */
	vtim_real		load_lru;
};

/* Fetch state, hangs off boc->stevedore_priv */
struct sdk_fetch {
	unsigned		magic;
#define SDK_FETCH_MAGIC		0x0f3a91c4
	uint8_t			*buf;
	size_t			pos;
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
	assert(off >= sc->data_start);
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

	if (sc->closed)
		return (-1);

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
	return (r);
}

static void
sdk_free_ext_locked(struct sdk_sc *sc, uint64_t off, uint64_t space)
{

	Lck_AssertHeld(&sc->mtx);
	if (space == 0 || sc->closed)
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

/* Release the body extents and take the object off the index list */
static void
sdk_obj_release(struct sdk_sc *sc, struct sdk_obj *o)
{
	unsigned u;

	Lck_Lock(&sc->mtx);
	if (o->flags & SDK_OF_LISTED) {
		VTAILQ_REMOVE(&sc->objs, o, list);
		o->flags &= ~SDK_OF_LISTED;
	}
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
	int cancelled;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(oc->boc, BOC_MAGIC);
	AN(sz);
	AN(ptr);
	stv = oc->stobj->stevedore;
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	o = sdk_getobj(oc);

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
		if (e == NULL)
			want = vmax_t(uint64_t, *sz, SDK_EXT_MIN);
		else
			want = vmax_t(uint64_t, *sz, e->space * 2);
		want = vmin_t(uint64_t, want, SDK_EXT_MAX);
		if (oc->boc->transit_buffer > 0)
			want = vmin_t(uint64_t, want,
			    oc->boc->transit_buffer);
		min = vmin_t(uint64_t, want, SDK_EXT_ACCEPT);
		Lck_Unlock(&oc->boc->mtx);

		while (sdk_alloc(o->sc, want, min, &ne)) {
			if (oc->boc->transit_buffer > 0 && n_ext > 0) {
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
				continue;
			}
			if (stv->lru == NULL || !LRU_NukeOne(wrk, stv->lru))
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

	if (fs->pos == SDK_WRBUF)
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
	struct sdk_obj *o;
	vtim_real t;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(boc, BOC_MAGIC);
	stv = oc->stobj->stevedore;
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	o = sdk_getobj(oc);

	sdk_fetch_fini(boc);

	if (boc->state == BOS_FINISHED || (o->flags & SDK_OF_LOADED)) {
		Lck_Lock(&o->sc->mtx);
		AZ(o->flags & SDK_OF_LISTED);
		VTAILQ_INSERT_TAIL(&o->sc->objs, o, list);
		o->flags |= SDK_OF_LISTED;
		Lck_Unlock(&o->sc->mtx);
	}

	if (stv->lru == NULL)
		return;
	if (o->flags & SDK_OF_LOADED) {
		t = o->load_lru;
		o->flags &= ~SDK_OF_LOADED;
	} else {
		if (isnan(wrk->lastused))
			wrk->lastused = VTIM_real();
		t = wrk->lastused;	// approx timestamp is OK
	}
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
		PTOK(pthread_cond_signal(&boc->cond));
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
	VSB_printf(vsb, "flags = 0x%x, len = %ju, n_ext = %u,\n",
	    o->flags, (uintmax_t)o->len, o->n_ext);
	for (u = 0; u < o->n_ext && u < 8; u++)
		VSB_printf(vsb, "ext = {off=%ju, len=%ju, space=%ju},\n",
		    (uintmax_t)o->ext[u].off, (uintmax_t)o->ext[u].len,
		    (uintmax_t)o->ext[u].space);
	VSB_indent(vsb, -2);
	VSB_cat(vsb, "},\n");
}

/*--------------------------------------------------------------------
 * Bans: we just keep the most recent full export and save it on close.
 * Returning zero from baninfo means incremental updates are fine with
 * us, since BAN_Shutdown() does a final full export anyway.
 */

static int v_matchproto_(storage_baninfo_f)
sdk_baninfo(const struct stevedore *stv, enum baninfo event,
    const uint8_t *ban, unsigned len)
{

	(void)stv;
	(void)event;
	(void)ban;
	(void)len;
	return (0);
}

static void v_matchproto_(storage_banexport_f)
sdk_banexport(const struct stevedore *stv, const uint8_t *bans, unsigned len)
{
	struct sdk_sc *sc;
	uint8_t *p;

	CAST_OBJ_NOTNULL(sc, stv->priv, SDK_SC_MAGIC);
	p = malloc(len);
	AN(p);
	memcpy(p, bans, len);
	Lck_Lock(&sc->mtx);
	free(sc->bans);
	sc->bans = p;
	sc->bans_len = len;
	Lck_Unlock(&sc->mtx);
}

/*--------------------------------------------------------------------
 * Header
 */

static void
sdk_hdr_sha(const struct sdk_hdr *hdr, uint8_t *sha)
{
	VSHA256_CTX ctx;

	VSHA256_Init(&ctx);
	VSHA256_Update(&ctx, hdr, offsetof(struct sdk_hdr, hdr_sha));
	VSHA256_Final(sha, &ctx);
}

static void
sdk_hdr_init(const struct sdk_sc *sc, struct sdk_hdr *hdr)
{

	memset(hdr, 0, sizeof *hdr);
	bprintf(hdr->magic, "%s", SDK_HDR_SIGNATURE);
	hdr->byteorder = SDK_BYTEORDER;
	hdr->version = SDK_VERSION;
	hdr->hdrsize = sizeof *hdr;
	hdr->mediasize = sc->mediasize;
	hdr->gran = SDK_GRAN;
}

static int
sdk_hdr_write(const struct sdk_sc *sc, struct sdk_hdr *hdr)
{
	uint8_t blk[SDK_HDR_SIZE];

	sdk_hdr_sha(hdr, hdr->hdr_sha);
	memset(blk, 0, sizeof blk);
	memcpy(blk, hdr, sizeof *hdr);
	if (sdk_pwrite(sc, blk, sizeof blk, 0))
		return (-1);
	return (fsync(sc->fd));
}

/* Returns a description of the problem, or NULL if the header is valid */
static const char *
sdk_hdr_check(const struct sdk_sc *sc, const struct sdk_hdr *hdr)
{
	uint8_t sha[VSHA256_LEN];
	unsigned u;
	uint64_t l = 0;

	if (memcmp(hdr->magic, SDK_HDR_SIGNATURE, sizeof SDK_HDR_SIGNATURE))
		return ("no header");
	sdk_hdr_sha(hdr, sha);
	if (memcmp(sha, hdr->hdr_sha, sizeof sha))
		return ("header checksum mismatch");
	if (hdr->byteorder != SDK_BYTEORDER || hdr->version != SDK_VERSION ||
	    hdr->hdrsize != sizeof *hdr || hdr->gran != SDK_GRAN)
		return ("incompatible format");
	if (hdr->mediasize != sc->mediasize)
		return ("size changed");
	if (!hdr->clean)
		return ("not shut down cleanly");
	if (hdr->n_idx_ext == 0 || hdr->n_idx_ext > SDK_IDX_EXT)
		return ("bad index");
	for (u = 0; u < hdr->n_idx_ext; u++) {
		if (hdr->idx_ext[u].off < sc->data_start ||
		    hdr->idx_ext[u].len > sc->data_end ||
		    hdr->idx_ext[u].off > sc->data_end - hdr->idx_ext[u].len)
			return ("bad index");
		l += hdr->idx_ext[u].len;
	}
	if (l < hdr->idx_len)
		return ("bad index");
	return (NULL);
}

/*--------------------------------------------------------------------
 * Index byte stream, written to and read from the extents listed in
 * the header.  A writer with no extents only counts and hashes.
 */

struct sdk_ios {
	const struct sdk_sc	*sc;
	const struct sdk_hdr_ext *ext;
	unsigned		n_ext;
	unsigned		cur;
	uint64_t		cur_pos;
	uint64_t		total;
	uint64_t		xfered;
	uint64_t		limit;
	VSHA256_CTX		sha;
	uint8_t			*buf;
	size_t			buf_len;
	size_t			buf_pos;
	int			err;
	int			nomem;
};

static void
sdk_ios_init(struct sdk_ios *io, const struct sdk_sc *sc,
    const struct sdk_hdr_ext *ext, unsigned n_ext, uint64_t limit)
{

	memset(io, 0, sizeof *io);
	io->sc = sc;
	io->ext = ext;
	io->n_ext = n_ext;
	io->limit = limit;
	VSHA256_Init(&io->sha);
	if (n_ext > 0) {
		io->buf = malloc(SDK_IOBUF);
		if (io->buf == NULL) {
			io->err = 1;
			io->nomem = 1;
		}
	}
}

/* Transfer the buffer to/from the extents */
static void
sdk_ios_xfer(struct sdk_ios *io, size_t len, int wr)
{
	const struct sdk_hdr_ext *e;
	uint8_t *p = io->buf;
	uint64_t l;

	while (len > 0 && !io->err) {
		if (io->cur >= io->n_ext) {
			io->err = 1;
			break;
		}
		e = &io->ext[io->cur];
		l = vmin_t(uint64_t, len, e->len - io->cur_pos);
		if (wr)
			io->err = sdk_pwrite(io->sc, p, l, e->off + io->cur_pos);
		else
			io->err = sdk_pread(io->sc, p, l, e->off + io->cur_pos);
		p += l;
		len -= l;
		io->cur_pos += l;
		if (io->cur_pos == e->len) {
			io->cur++;
			io->cur_pos = 0;
		}
	}
}

static void
sdk_ios_put(struct sdk_ios *io, const void *ptr, size_t len)
{
	const uint8_t *p = ptr;
	size_t l;

	io->total += len;
	VSHA256_Update(&io->sha, ptr, len);
	if (io->buf == NULL)
		return;
	while (len > 0) {
		l = vmin_t(size_t, len, SDK_IOBUF - io->buf_pos);
		memcpy(io->buf + io->buf_pos, p, l);
		io->buf_pos += l;
		p += l;
		len -= l;
		if (io->buf_pos == SDK_IOBUF) {
			sdk_ios_xfer(io, io->buf_pos, 1);
			io->buf_pos = 0;
		}
	}
}

static int
sdk_ios_flush(struct sdk_ios *io)
{

	if (io->buf_pos > 0)
		sdk_ios_xfer(io, io->buf_pos, 1);
	io->buf_pos = 0;
	return (io->err);
}


static int
sdk_ios_get(struct sdk_ios *io, void *ptr, size_t len)
{
	uint8_t *p = ptr;
	size_t l;

	if (io->err || len > io->limit - io->total) {
		io->err = 1;
		return (-1);
	}
	io->total += len;
	while (len > 0) {
		if (io->buf_pos == io->buf_len) {
			l = vmin_t(uint64_t, SDK_IOBUF,
			    io->limit - io->xfered);
			assert(l > 0);
			sdk_ios_xfer(io, l, 0);
			if (io->err)
				return (-1);
			io->xfered += l;
			io->buf_len = l;
			io->buf_pos = 0;
		}
		l = vmin_t(size_t, len, io->buf_len - io->buf_pos);
		memcpy(p, io->buf + io->buf_pos, l);
		VSHA256_Update(&io->sha, p, l);
		io->buf_pos += l;
		p += l;
		len -= l;
	}
	return (0);
}

static void
sdk_ios_fini(struct sdk_ios *io)
{

	free(io->buf);
	io->buf = NULL;
}

/*--------------------------------------------------------------------
 * Object records
 */

struct sdk_rec {
	uint32_t		magic;
	uint32_t		n_ext;
	uint8_t			digest[DIGEST_LEN];
	double			t_origin;
	double			ban;
	double			last_lru;
	float			ttl;
	float			grace;
	float			keep;
	uint16_t		oa_present;
	uint8_t			flags;
	uint8_t			pad;
};

#define SDK_OC_FLAGS	(OC_F_HFM | OC_F_HFP)

#define SDK_OC_NOSAVE	(OC_F_WITHDRAWN | OC_F_BUSY | OC_F_CANCEL | \
			 OC_F_PRIVATE | OC_F_FAILED | OC_F_DYING)

static void
sdk_save_obj(struct sdk_ios *io, const struct sdk_obj *o)
{
	const struct objcore *oc;
	struct sdk_rec rec;
	uint32_t l;
	unsigned u;

	oc = o->oc;
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	CHECK_OBJ_NOTNULL(oc->objhead, OBJHEAD_MAGIC);

	memset(&rec, 0, sizeof rec);
	rec.magic = SDK_REC_SIGNATURE;
	rec.n_ext = o->n_ext;
	memcpy(rec.digest, oc->objhead->digest, sizeof rec.digest);
	rec.t_origin = oc->t_origin;
	rec.ttl = oc->ttl;
	rec.grace = oc->grace;
	rec.keep = oc->keep;
	rec.ban = BAN_Time(oc->ban);
	rec.last_lru = oc->last_lru;
	rec.oa_present = oc->oa_present;
	rec.flags = oc->flags & SDK_OC_FLAGS;
	sdk_ios_put(io, &rec, sizeof rec);

#define OBJ_FIXATTR(U, n, s)					\
	sdk_ios_put(io, o->fa_##n, sizeof o->fa_##n);
#include "tbl/obj_attr.h"

#define OBJ_VARATTR(U, n)					\
	l = o->va_##n##_len;					\
	sdk_ios_put(io, &l, sizeof l);				\
	if (l > 0)						\
		sdk_ios_put(io, o->va_##n, l);
#include "tbl/obj_attr.h"

#define OBJ_AUXATTR(U, n)					\
	l = o->aa_##n##_len;					\
	sdk_ios_put(io, &l, sizeof l);				\
	if (l > 0)						\
		sdk_ios_put(io, o->aa_##n, l);
#include "tbl/obj_attr.h"

	for (u = 0; u < o->n_ext; u++)
		sdk_ios_put(io, &o->ext[u], sizeof o->ext[u]);
}

/* Decide which objects go in the index */
static unsigned
sdk_save_mark(struct sdk_sc *sc, vtim_real now)
{
	const struct objcore *oc;
	struct sdk_obj *o;
	unsigned n = 0;

	Lck_AssertHeld(&sc->mtx);
	VTAILQ_FOREACH(o, &sc->objs, list) {
		CHECK_OBJ_NOTNULL(o, SDK_OBJ_MAGIC);
		o->flags &= ~SDK_OF_SAVE;
		oc = o->oc;
		CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
		if (oc->flags & SDK_OC_NOSAVE)
			continue;
		if (oc->boc != NULL || oc->objhead == NULL || oc->ban == NULL)
			continue;
		if (EXP_WHEN(oc) <= now)
			continue;
		o->flags |= SDK_OF_SAVE;
		n++;
	}
	return (n);
}

static void
sdk_save_stream(const struct sdk_sc *sc, struct sdk_ios *io)
{
	const struct sdk_obj *o;
	uint32_t u;

	Lck_AssertHeld(&sc->mtx);
	u = sc->bans_len;
	sdk_ios_put(io, &u, sizeof u);
	if (u > 0)
		sdk_ios_put(io, sc->bans, u);

	VTAILQ_FOREACH(o, &sc->objs, list)
		if (o->flags & SDK_OF_SAVE)
			sdk_save_obj(io, o);

	u = SDK_REC_END;
	sdk_ios_put(io, &u, sizeof u);
}

static uint64_t
sdk_save_size(const struct sdk_sc *sc, const struct sdk_obj *o)
{
	struct sdk_ios io;

	sdk_ios_init(&io, sc, NULL, 0, 0);
	sdk_save_obj(&io, o);
	return (io.total);
}

/*
 * Get space for the index, all or nothing.
 */
static int
sdk_save_alloc(struct sdk_sc *sc, struct sdk_hdr *hdr, uint64_t len)
{
	struct sdk_ext e;
	uint64_t rem;
	unsigned u;

	Lck_AssertHeld(&sc->mtx);
	rem = sdk_roundup(len);
	hdr->n_idx_ext = 0;
	while (rem > 0 && hdr->n_idx_ext < SDK_IDX_EXT) {
		if (sdk_alloc_locked(sc, rem, SDK_GRAN, &e))
			break;
		hdr->idx_ext[hdr->n_idx_ext].off = e.off;
		hdr->idx_ext[hdr->n_idx_ext].len = e.space;
		hdr->n_idx_ext++;
		rem -= e.space;
	}
	if (rem == 0)
		return (0);
	for (u = 0; u < hdr->n_idx_ext; u++)
		sdk_free_insert(sc, hdr->idx_ext[u].off, hdr->idx_ext[u].len);
	hdr->n_idx_ext = 0;
	return (-1);
}

/*
 * Give up an object to make room for the index.  We can only do that
 * if nobody but expiry holds a reference, and we make sure nobody gets
 * one, because its extents are about to be overwritten.
 */
static int
sdk_save_sacrifice(struct sdk_sc *sc, struct sdk_obj *o)
{
	struct objcore *oc;
	struct objhead *oh;
	int r = 0;
	unsigned u;

	Lck_AssertHeld(&sc->mtx);
	oc = o->oc;
	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	oh = oc->objhead;
	CHECK_OBJ_NOTNULL(oh, OBJHEAD_MAGIC);

	if (oc->refcnt != 1 || Lck_Trylock(&oh->mtx))
		return (0);
	if (oc->refcnt == 1 && !(oc->flags & OC_F_DYING)) {
		oc->flags |= OC_F_DYING;
		r = 1;
	}
	Lck_Unlock(&oh->mtx);
	if (!r)
		return (0);

	o->flags &= ~SDK_OF_SAVE;
	for (u = 0; u < o->n_ext; u++) {
		sdk_free_ext_locked(sc, o->ext[u].off, o->ext[u].space);
		if (o->ext[u].space > 0)
			sc->stats->g_alloc--;
	}
	o->n_ext = 0;
	o->len = 0;
	return (1);
}

/*
 * Write the index and mark the header clean.  Once we start, no more
 * space is handed out and nothing is returned to the free map, so the
 * index and the extents it references cannot be overwritten before
 * the process exits.
 *
 * A full cache may not have room for the index, in which case we give
 * up objects, oldest first, until it fits.
 */
static void
sdk_save(struct sdk_sc *sc)
{
	struct sdk_hdr hdr;
	struct sdk_ios io;
	struct sdk_obj *o;
	uint64_t len, sz;
	unsigned n, dropped = 0;
	const char *err = NULL;
	vtim_real t0;

	t0 = VTIM_mono();
	sdk_hdr_init(sc, &hdr);

	Lck_Lock(&sc->mtx);
	n = sdk_save_mark(sc, VTIM_real());

	/* First pass: size the index */
	sdk_ios_init(&io, sc, NULL, 0, 0);
	sdk_save_stream(sc, &io);
	len = io.total;
	sdk_ios_fini(&io);

	o = VTAILQ_FIRST(&sc->objs);
	while (sdk_save_alloc(sc, &hdr, len)) {
		for (; o != NULL; o = VTAILQ_NEXT(o, list)) {
			if (!(o->flags & SDK_OF_SAVE))
				continue;
			sz = sdk_save_size(sc, o);
			if (sdk_save_sacrifice(sc, o)) {
				len -= sz;
				n--;
				dropped++;
				break;
			}
		}
		if (o == NULL) {
			err = "not enough free space for the index";
			break;
		}
		o = VTAILQ_NEXT(o, list);
	}
	sc->closed = 1;

	/* Second pass: write it */
	if (err == NULL) {
		sdk_ios_init(&io, sc, hdr.idx_ext, hdr.n_idx_ext, 0);
		sdk_save_stream(sc, &io);
		if (sdk_ios_flush(&io))
			err = io.nomem ? "out of memory for index buffer" :
			    "index write error";
		else
			assert(io.total == len);
		VSHA256_Final(hdr.idx_sha, &io.sha);
		sdk_ios_fini(&io);
	}

	/* Make sure bodies and index are on disk before we say so */
	if (err == NULL && fsync(sc->fd))
		err = "fsync error";

	if (err == NULL) {
		hdr.clean = 1;
		hdr.idx_len = len;
		if (sdk_hdr_write(sc, &hdr))
			err = "header write error";
	}
	Lck_Unlock(&sc->mtx);

	if (err != NULL)
		printf("DISK.%s: content not saved: %s\n",
		    sc->stv->ident, err);
	else
		printf("DISK.%s: saved %u objects (%u dropped for space),"
		    " index %ju bytes in %u extents, %.3fs\n",
		    sc->stv->ident, n, dropped, (uintmax_t)len,
		    hdr.n_idx_ext, VTIM_mono() - t0);
}

static void v_matchproto_(storage_close_f)
sdk_close(const struct stevedore *stv, int warn)
{
	struct sdk_sc *sc;

	ASSERT_CLI();
	CAST_OBJ_NOTNULL(sc, stv->priv, SDK_SC_MAGIC);
	if (warn)
		return;
	sdk_save(sc);
}

/*--------------------------------------------------------------------
 * Loading the index
 */

struct sdk_load {
	struct sdk_obj		*o;
	struct sdk_rec		rec;
	struct ban		*ban;
};

struct sdk_loadctx {
	unsigned		magic;
#define SDK_LOADCTX_MAGIC	0x3c8e57a9
	struct sdk_sc		*sc;
	struct sdk_load		*lo;
	unsigned		n;
	unsigned		l;
	uint8_t			*bans;
	uint32_t		bans_len;
	int			nomem;
};

static void
sdk_load_drop(struct sdk_load *lo)
{

	if (lo->o == NULL)
		return;
	free(lo->o->ext);
	sdk_obj_free_attrs(lo->o, 0);
	FREE_OBJ(lo->o);
}

static void
sdk_loadctx_fini(struct sdk_loadctx *lc)
{
	unsigned u;

	for (u = 0; u < lc->n; u++)
		sdk_load_drop(&lc->lo[u]);
	free(lc->lo);
	free(lc->bans);
	lc->lo = NULL;
	lc->bans = NULL;
	lc->n = lc->l = 0;
}

static int
sdk_load_attr(struct sdk_ios *io, uint8_t **pp, unsigned *plen)
{
	uint32_t l;

	if (sdk_ios_get(io, &l, sizeof l))
		return (-1);
	if (l == 0)
		return (0);
	if (l > SDK_MAX_ATTR)
		return (-1);
	*pp = malloc(l);
	if (*pp == NULL) {
		io->nomem = 1;
		return (-1);
	}
	*plen = l;
	return (sdk_ios_get(io, *pp, l));
}

static int
sdk_load_obj(const struct sdk_sc *sc, struct sdk_ios *io, struct sdk_load *lo)
{
	struct sdk_obj *o;
	struct sdk_ext *e;
	unsigned u;

	if (sdk_ios_get(io, (uint8_t *)&lo->rec + sizeof lo->rec.magic,
	    sizeof lo->rec - sizeof lo->rec.magic))
		return (-1);
	if (lo->rec.n_ext > SDK_MAX_EXT)
		return (-1);

	ALLOC_OBJ(o, SDK_OBJ_MAGIC);
	if (o == NULL) {
		io->nomem = 1;
		return (-1);
	}
	lo->o = o;

#define OBJ_FIXATTR(U, n, s)					\
	if (sdk_ios_get(io, o->fa_##n, sizeof o->fa_##n))	\
		return (-1);
#include "tbl/obj_attr.h"

#define OBJ_VARATTR(U, n)					\
	if (sdk_load_attr(io, &o->va_##n, &o->va_##n##_len))	\
		return (-1);
#include "tbl/obj_attr.h"

#define OBJ_AUXATTR(U, n)					\
	if (sdk_load_attr(io, &o->aa_##n, &o->aa_##n##_len))	\
		return (-1);
#include "tbl/obj_attr.h"

	if (lo->rec.n_ext > 0) {
		o->ext = calloc(lo->rec.n_ext, sizeof *o->ext);
		if (o->ext == NULL) {
			io->nomem = 1;
			return (-1);
		}
		o->n_ext = o->l_ext = lo->rec.n_ext;
		if (sdk_ios_get(io, o->ext, o->n_ext * sizeof *o->ext))
			return (-1);
	}
	for (u = 0; u < o->n_ext; u++) {
		e = &o->ext[u];
		if (e->off % SDK_GRAN || e->space % SDK_GRAN ||
		    e->space == 0 || e->len > e->space ||
		    e->off < sc->data_start || e->space > sc->data_end ||
		    e->off > sc->data_end - e->space)
			return (-1);
		o->len += e->len;
	}
	return (0);
}

static int
sdk_load_index(const struct sdk_sc *sc, const struct sdk_hdr *hdr,
    struct sdk_loadctx *lc)
{
	struct sdk_ios io;
	uint8_t sha[VSHA256_LEN];
	struct sdk_load *lo, *p;
	uint32_t magic;
	unsigned l;
	int r = -1;

	/* Verify the whole index before we trust any of it */
	sdk_ios_init(&io, sc, hdr->idx_ext, hdr->n_idx_ext, hdr->idx_len);
	if (io.nomem) {
		lc->nomem = 1;
		sdk_ios_fini(&io);
		return (-1);
	}
	while (io.total < io.limit) {
		if (io.buf_pos == io.buf_len) {
			io.buf_len = vmin_t(uint64_t, SDK_IOBUF,
			    io.limit - io.xfered);
			io.buf_pos = 0;
			sdk_ios_xfer(&io, io.buf_len, 0);
			if (io.err)
				break;
			io.xfered += io.buf_len;
		}
		VSHA256_Update(&io.sha, io.buf, io.buf_len);
		io.total += io.buf_len;
		io.buf_pos = io.buf_len;
	}
	VSHA256_Final(sha, &io.sha);
	sdk_ios_fini(&io);
	if (io.err || memcmp(sha, hdr->idx_sha, sizeof sha))
		return (-1);

	sdk_ios_init(&io, sc, hdr->idx_ext, hdr->n_idx_ext, hdr->idx_len);
	do {
		if (sdk_ios_get(&io, &lc->bans_len, sizeof lc->bans_len))
			break;
		if (lc->bans_len > 0) {
			if (lc->bans_len > hdr->idx_len)
				break;
			lc->bans = malloc(lc->bans_len);
			if (lc->bans == NULL) {
				io.nomem = 1;
				break;
			}
			if (sdk_ios_get(&io, lc->bans, lc->bans_len))
				break;
		}
		while (1) {
			if (sdk_ios_get(&io, &magic, sizeof magic))
				break;
			if (magic == SDK_REC_END) {
				if (io.total == hdr->idx_len)
					r = 0;
				break;
			}
			if (magic != SDK_REC_SIGNATURE)
				break;
			if (lc->n == lc->l) {
				l = lc->l ? lc->l * 2 : 1024;
				p = realloc(lc->lo, (size_t)l * sizeof *p);
				if (p == NULL) {
					io.nomem = 1;
					break;
				}
				lc->lo = p;
				lc->l = l;
			}
			lo = &lc->lo[lc->n++];
			memset(lo, 0, sizeof *lo);
			lo->rec.magic = magic;
			if (sdk_load_obj(sc, &io, lo))
				break;
		}
	} while (0);
	lc->nomem = io.nomem;
	sdk_ios_fini(&io);
	if (r)
		sdk_loadctx_fini(lc);
	return (r);
}

static int
sdk_ext_cmp(const void *a, const void *b)
{
	const struct sdk_ext *ea = a, *eb = b;

	if (ea->off < eb->off)
		return (-1);
	return (ea->off > eb->off);
}

static int
sdk_lru_cmp(const void *a, const void *b)
{
	const struct sdk_load *la = a, *lb = b;

	if (la->rec.last_lru < lb->rec.last_lru)
		return (-1);
	return (la->rec.last_lru > lb->rec.last_lru);
}

/*
 * Drop objects we will not restore, then build the free map from the
 * extents of the rest.  Returns non-zero if extents overlap, in which
 * case nothing can be trusted.
 */
static int
sdk_load_prepare(struct sdk_sc *sc, struct sdk_loadctx *lc, vtim_real now)
{
	struct sdk_ext *all = NULL;
	struct sdk_load *lo;
	unsigned u, v, n_all = 0;
	uint64_t pos;

	for (u = v = 0; u < lc->n; u++) {
		lo = &lc->lo[u];
		if (EXP_WHEN(&lo->rec) > now)
			lo->ban = BAN_FindBan(lo->rec.ban);
		if (lo->ban == NULL) {
			sdk_load_drop(lo);
			continue;
		}
		if (isnan(lo->rec.last_lru))
			lo->rec.last_lru = now;
		n_all += lo->o->n_ext;
		lc->lo[v++] = *lo;
	}
	lc->n = v;

	if (n_all > 0) {
		all = malloc(n_all * sizeof *all);
		if (all == NULL) {
			lc->nomem = 1;
			return (-1);
		}
	}
	for (u = v = 0; u < lc->n; u++) {
		if (lc->lo[u].o->n_ext > 0)
			memcpy(all + v, lc->lo[u].o->ext,
			    lc->lo[u].o->n_ext * sizeof *all);
		v += lc->lo[u].o->n_ext;
	}
	assert(v == n_all);
	if (n_all > 0)
		qsort(all, n_all, sizeof *all, sdk_ext_cmp);

	pos = sc->data_start;
	for (u = 0; u < n_all; u++) {
		if (all[u].off < pos) {
			free(all);
			return (-1);
		}
		pos = all[u].off + all[u].space;
	}

	Lck_Lock(&sc->mtx);
	pos = sc->data_start;
	for (u = 0; u < n_all; u++) {
		if (all[u].off > pos)
			sdk_free_insert(sc, pos, all[u].off - pos);
		pos = all[u].off + all[u].space;
		sc->stats->g_alloc++;
		sc->stats->g_bytes += all[u].space;
	}
	if (sc->data_end > pos)
		sdk_free_insert(sc, pos, sc->data_end - pos);
	sc->stats->g_space =
	    (sc->data_end - sc->data_start) - sc->stats->g_bytes;
	Lck_Unlock(&sc->mtx);
	free(all);

	/* Insert least recently used first, so the LRU list comes out right */
	if (lc->n > 0)
		qsort(lc->lo, lc->n, sizeof *lc->lo, sdk_lru_cmp);
	return (0);
}

static void * v_matchproto_(bgthread_t)
sdk_load_thread(struct worker *wrk, void *priv)
{
	struct sdk_loadctx *lc;
	struct sdk_load *lo;
	struct objcore *oc;
	struct sdk_sc *sc;
	unsigned u;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CAST_OBJ_NOTNULL(lc, priv, SDK_LOADCTX_MAGIC);
	sc = lc->sc;

	for (u = 0; u < lc->n; u++) {
		lo = &lc->lo[u];
		CHECK_OBJ_NOTNULL(lo->o, SDK_OBJ_MAGIC);
		AN(lo->ban);

		oc = ObjNew(wrk);
		lo->o->sc = sc;
		lo->o->oc = oc;
		lo->o->flags |= SDK_OF_LOADED;
		lo->o->load_lru = lo->rec.last_lru;
		oc->stobj->stevedore = sc->stv;
		oc->stobj->priv = lo->o;
		lo->o = NULL;
		EXP_COPY(oc, &lo->rec);
		oc->flags |= lo->rec.flags & SDK_OC_FLAGS;
		oc->oa_present = lo->rec.oa_present;
		oc->refcnt++;
		wrk->stats->n_object++;
		HSH_Insert(wrk, lo->rec.digest, oc, lo->ban);
		AN(oc->ban);
		HSH_DerefBoc(wrk, oc);
		(void)HSH_DerefObjCore(wrk, &oc);
	}
	Lck_Lock(&sc->mtx);
	sc->stats->c_restored += lc->n;
	Lck_Unlock(&sc->mtx);
	return (NULL);
}

/*--------------------------------------------------------------------
 * Open the storage in the cache process
 */

static void
sdk_open_load(struct sdk_sc *sc, const struct sdk_hdr *hdr)
{
	struct sdk_loadctx lc[1];
	pthread_t thr;
	vtim_real t0;

	t0 = VTIM_mono();
	INIT_OBJ(lc, SDK_LOADCTX_MAGIC);
	lc->sc = sc;
	if (sdk_load_index(sc, hdr, lc)) {
		printf("DISK.%s: starting empty: %s\n",
		    sc->stv->ident, lc->nomem ?
		    "out of memory loading index" : "index corrupt");
		return;
	}

	if (lc->bans_len > 0)
		BAN_Reload(lc->bans, lc->bans_len);

	if (sdk_load_prepare(sc, lc, VTIM_real())) {
		printf("DISK.%s: starting empty: %s\n",
		    sc->stv->ident, lc->nomem ?
		    "out of memory preparing free map" : "extents overlap");
		sdk_loadctx_fini(lc);
		return;
	}

	/* HSH_Insert() needs a proper worker, borrow a thread for it */
	WRK_BgThread(&thr, "disk-load", sdk_load_thread, lc);
	PTOK(pthread_join(thr, NULL));

	printf("DISK.%s: restored %u objects in %.3fs\n",
	    sc->stv->ident, lc->n, VTIM_mono() - t0);
	sdk_loadctx_fini(lc);
}

static void v_matchproto_(storage_open_f)
sdk_open(struct stevedore *stv)
{
	uint8_t blk[SDK_HDR_SIZE];
	struct sdk_hdr hdr;
	struct sdk_sc *sc;
	const char *why;

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
	VTAILQ_INIT(&sc->objs);

	if (sdk_pread(sc, blk, sizeof blk, 0))
		why = "header read error";
	else {
		memcpy(&hdr, blk, sizeof hdr);
		why = sdk_hdr_check(sc, &hdr);
	}

	/*
	 * Whatever happens from here on, the content on disk is only
	 * valid again after an orderly sdk_close().  This must hit the
	 * disk before we write anything else.
	 */
	{
		struct sdk_hdr nhdr;

		sdk_hdr_init(sc, &nhdr);
		if (sdk_hdr_write(sc, &nhdr))
			ARGV_ERR("(-sdisk) %s: header write error: %s\n",
			    sc->filename, VAS_errtxt(errno));
	}

	if (why == NULL)
		sdk_open_load(sc, &hdr);
	else
		printf("DISK.%s: starting empty: %s\n", stv->ident, why);

	if (VRBT_EMPTY(&sc->free_off) && sc->stats->g_bytes == 0) {
		/* Nothing loaded, the whole thing is free */
		Lck_Lock(&sc->mtx);
		sdk_free_insert(sc, sc->data_start,
		    sc->data_end - sc->data_start);
		sc->stats->g_space = sc->data_end - sc->data_start;
		Lck_Unlock(&sc->mtx);
	}
}

/*--------------------------------------------------------------------
 * Configure the storage before entering the worker jail
 */

static void v_matchproto_(storage_init_f)
sdk_init(struct stevedore *parent, int ac, char * const *av)
{
	const char *size = NULL;
	struct sdk_sc *sc;
	unsigned gran = SDK_HDR_SIZE;
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
	/* FileSize rounds the media size; extents use SDK_GRAN separately. */
	sc->mediasize = STV_FileSize(sc->fd, size, &gran, "-sdisk");
	if (sc->mediasize < SDK_HDR_SIZE + SDK_EXT_MAX)
		ARGV_ERR("(-sdisk) size too small\n");
	if (VFIL_allocate(sc->fd, (off_t)sc->mediasize, 0))
		ARGV_ERR("(-sdisk) allocation error: %s\n",
		    VAS_errtxt(errno));
	sc->data_start = SDK_HDR_SIZE;
	sc->data_end = sc->mediasize & ~((uint64_t)SDK_GRAN - 1);
	parent->priv = sc;
}

const struct stevedore sdk_stevedore = {
	.magic		=	STEVEDORE_MAGIC,
	.name		=	"disk",
	.init		=	sdk_init,
	.open		=	sdk_open,
	.close		=	sdk_close,
	.allocobj	=	sdk_allocobj,
	.baninfo	=	sdk_baninfo,
	.banexport	=	sdk_banexport,
	.panic		=	sdk_panic,
	.methods	=	&sdk_methods,
};
