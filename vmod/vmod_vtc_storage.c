/*-
 * Copyright 2021,2023,2026 UPLEX - Nils Goroll Systemoptimierung
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
 * interpose storage methods for testing purposes
 */

#include "config.h"

#include <stdlib.h>

#include "cache/cache_int.h"
#include "cache/cache_obj.h"
#include "storage/storage.h"

#include "vcc_vtc_if.h"

/* ----------------------------------------
 * stvi
 */
// override parameters
struct stvi_param {
	ssize_t			maxspace;
	ssize_t			frag;
};

// created once, only freed when the vmod goes cold
// i for interposer
struct stvi {
	unsigned			magic;
#define	STVI_MAGIC			0x85ff17c0
	VRBT_ENTRY(stvi)		tree;
	uintptr_t			stv;

	// original contents, copied on stvi creation
	struct stevedore		stv_save;
	struct obj_methods		om_save;
	// original methods pointer, for revert()
	const struct obj_methods	*om;
	void				*freeme;

	struct stvi_param		param;
};

static inline int
stvi_cmp(const struct stvi *s1, const struct stvi *s2)
{
	if (s1->stv < s2->stv)
		return (-1);
	if (s1->stv > s2->stv)
		return (1);
	return (0);
}

VRBT_HEAD(stvi_head, stvi);
VRBT_GENERATE_REMOVE_COLOR(stvi_head, stvi, tree, static)
VRBT_GENERATE_REMOVE(stvi_head, stvi, tree, static)
VRBT_GENERATE_FIND(stvi_head, stvi, tree, stvi_cmp, static)
VRBT_GENERATE_INSERT_COLOR(stvi_head, stvi, tree, static)
VRBT_GENERATE_INSERT_FINISH(stvi_head, stvi, tree, static)
VRBT_GENERATE_INSERT(stvi_head, stvi, tree, stvi_cmp, static)
VRBT_GENERATE_NEXT(stvi_head, stvi, tree, static)
VRBT_GENERATE_MINMAX(stvi_head, stvi, tree, static)

static struct stvi_head stvi_head = VRBT_INITIALIZER(stvi);
static pthread_mutex_t stvi_mtx = PTHREAD_MUTEX_INITIALIZER;

// only return if exists
static struct stvi *
stvi_find(VCL_STEVEDORE stv)
{
	struct stvi needle;
	struct stvi *si;

	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);
	needle.stv = (uintptr_t)TRUST_ME(stv);

	PTOK(pthread_mutex_lock(&stvi_mtx));
	si = VRBT_FIND(stvi_head, &stvi_head, &needle);
	PTOK(pthread_mutex_unlock(&stvi_mtx));

	CHECK_OBJ_ORNULL(si, STVI_MAGIC);
	return (si);
}

// create if does not exist
static struct stvi *
stvi_get(VCL_STEVEDORE stv)
{
	struct stevedore *wstv;
	struct obj_methods *wom;
	struct stvi *si, *old;

	si = stvi_find(stv);
	if (si)
		return (si);

	ALLOC_OBJ(si, STVI_MAGIC);
	AN(si);
	si->stv = (uintptr_t)TRUST_ME(stv);

	PTOK(pthread_mutex_lock(&stvi_mtx));
	old = VRBT_INSERT(stvi_head, &stvi_head, si);
	// copy under the mutex to make sure that only the first _get() copies
	if (old == NULL) {
		si->stv_save = *stv;
		si->om_save = *stv->methods;
	}
	PTOK(pthread_mutex_unlock(&stvi_mtx));

	if (old) {
		FREE_OBJ(si);
		CHECK_OBJ(old, STVI_MAGIC);
		return (old);
	}

	// ensure methods are writable
	si->om = stv->methods;
	wom = malloc(sizeof *wom);
	AN(wom);
	*wom = *stv->methods;

	wstv = TRUST_ME(stv);
	wstv->methods = wom;

	return (si);
}

/* ----------------------------------------
 * obji
 */
// freed via objfree
struct obji {
	unsigned		magic;
#define OBJI_MAGIC		0x65fc7452
	VRBT_ENTRY(obji)	tree;
	uintptr_t		oc;

	// remaining maxspace
	ssize_t			canalloc;
};

static inline int
obji_cmp(const struct obji *oi1, const struct obji *oi2)
{
	if (oi1->oc < oi2->oc)
		return (-1);
	if (oi1->oc > oi2->oc)
		return (1);
	return (0);
}

VRBT_HEAD(obji_head, obji);
VRBT_GENERATE_REMOVE_COLOR(obji_head, obji, tree, static)
VRBT_GENERATE_REMOVE(obji_head, obji, tree, static)
VRBT_GENERATE_FIND(obji_head, obji, tree, obji_cmp, static)
VRBT_GENERATE_INSERT_COLOR(obji_head, obji, tree, static)
VRBT_GENERATE_INSERT_FINISH(obji_head, obji, tree, static)
VRBT_GENERATE_INSERT(obji_head, obji, tree, obji_cmp, static)
//VRBT_GENERATE_NEXT(obji_head, obji, tree, static)
//VRBT_GENERATE_MINMAX(obji_head, obji, tree, static)

static struct obji_head obji_head = VRBT_INITIALIZER(obji);
static pthread_mutex_t obji_mtx = PTHREAD_MUTEX_INITIALIZER;

// only return if exists
static struct obji *
obji_find(const struct objcore *oc)
{
	struct obji needle;
	struct obji *oi;

	needle.oc = (uintptr_t)oc;

	PTOK(pthread_mutex_lock(&obji_mtx));
	oi = VRBT_FIND(obji_head, &obji_head, &needle);
	PTOK(pthread_mutex_unlock(&obji_mtx));

	CHECK_OBJ_ORNULL(oi, OBJI_MAGIC);
	return (oi);
}

// creat if does not exist
static struct obji *
obji_get(const struct objcore *oc)
{
	struct obji *oi, *old;

	oi = obji_find(oc);
	if (oi)
		return (oi);

	ALLOC_OBJ(oi, OBJI_MAGIC);
	AN(oi);
	oi->oc = (uintptr_t)TRUST_ME(oc);

	PTOK(pthread_mutex_lock(&obji_mtx));
	old = VRBT_INSERT(obji_head, &obji_head, oi);
	PTOK(pthread_mutex_unlock(&obji_mtx));

	if (old) {
		FREE_OBJ(oi);
		CHECK_OBJ(old, OBJI_MAGIC);
		return (old);
	}
	return (oi);
}

static void
obji_free(const struct objcore *oc)
{
	struct obji needle;
	struct obji *oi;

	needle.oc = (uintptr_t)oc;

	PTOK(pthread_mutex_lock(&obji_mtx));
	oi = VRBT_FIND(obji_head, &obji_head, &needle);
	if (oi)
		VRBT_REMOVE(obji_head, &obji_head, oi);
	PTOK(pthread_mutex_unlock(&obji_mtx));

	if (oi == NULL)
		return;

	FREE_OBJ(oi);
}

// copy all stv pointers we are modifying
static void
stvcpy(struct stevedore *dst, const struct stevedore *src)
{

	CHECK_OBJ_NOTNULL(dst, STEVEDORE_MAGIC);
	CHECK_OBJ_NOTNULL(src, STEVEDORE_MAGIC);
	dst->allocobj = src->allocobj;
	dst->allocbuf = src->allocbuf;
}

// copy all om ponters we are modifying
static void
omcpy(struct obj_methods *dst, const struct obj_methods *src)
{

	dst->objfree = src->objfree;
	dst->objgetspace = src->objgetspace;
	dst->objextend = src->objextend;
}

// whenever we hack the stv & om pointers, we first
// restore the original state
#define REVERT(si, stv, wstv, wom)		\
	wstv = TRUST_ME(stv);			\
	stvcpy(wstv, &si->stv_save);		\
	wom = TRUST_ME(stv->methods);		\
	omcpy(wom, &si->om_save)

#define PATCH_BEGIN(si, stv, wstv, wom)		\
	PTOK(pthread_mutex_lock(&stvi_mtx));	\
	REVERT(si, stv, wstv, wom)

#define PATCH_END()				\
	PTOK(pthread_mutex_unlock(&stvi_mtx))

// when the last vcl using us goes cold, remove ourselves from all stevedores
// and objects. This is a bit racy, because the updated method pointers do not
// get visible immediately, and the methods assert that their stvi exists. Also,
// we had replaced obj_method with a malloc'ed copy, so we need to wait until we
// can assume safely that no code is using that pointer any more.
//
// Hence, do this in passes: First, restore all the stv methods, then destroy
// all the objis and finally destroy the stvis.
static void
revert(void)
{
	struct stevedore *stv;
	struct obji *oi;
	struct stvi *si;
	int check = 0;

	// pass 1: restore all pointers
	PTOK(pthread_mutex_lock(&stvi_mtx));
	VRBT_FOREACH(si, stvi_head, &stvi_head) {
		CHECK_OBJ(si, STVI_MAGIC);
		check++;
		CAST_OBJ_NOTNULL(stv, (void *)si->stv, STEVEDORE_MAGIC);
		stvcpy(stv, &si->stv_save);
		AZ(si->freeme);
		si->freeme = TRUST_ME(stv->methods);
		AN(si->om);
		stv->methods = si->om;
	}
	PTOK(pthread_mutex_unlock(&stvi_mtx));

	if (check > 0)
		sleep (1);

	// pass 2: free all objis: No interposer callback should run any more
	PTOK(pthread_mutex_lock(&obji_mtx));
	while ((oi = VRBT_ROOT(&obji_head)) != NULL) {
		CHECK_OBJ(oi, OBJI_MAGIC);
		VRBT_REMOVE(obji_head, &obji_head, oi);
		FREE_OBJ(oi);
	}
	PTOK(pthread_mutex_unlock(&obji_mtx));

	// pass 3: free
	PTOK(pthread_mutex_lock(&stvi_mtx));
	while ((si = VRBT_ROOT(&stvi_head)) != NULL) {
		CHECK_OBJ(si, STVI_MAGIC);
		check--;
		VRBT_REMOVE(stvi_head, &stvi_head, si);
		AN(si->freeme);
		free(si->freeme);
		FREE_OBJ(si);
	}
	PTOK(pthread_mutex_unlock(&stvi_mtx));
	assert(check == 0);
}

static unsigned ref = 0;

int v_matchproto_(vmod_event_f)
vmod_vcl_event(VRT_CTX, struct vmod_priv *priv, enum vcl_event_e e)
{

	(void)ctx;
	(void)priv;

	switch (e) {
	case VCL_EVENT_WARM:
		ref++;
		return (0);
	case VCL_EVENT_COLD:
		AN(ref);
		if (--ref == 0)
			revert();
		return (0);
	default:
		return (0);
	}
}

VCL_VOID
vmod_storage_revert(VRT_CTX, VCL_STEVEDORE stv)
{
	struct stevedore *wstv;
	struct obj_methods *wom;
	struct stvi *si;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);

	si = stvi_find(stv);
	if (si == NULL)
		return;

	PATCH_BEGIN(si, stv, wstv, wom);
	PATCH_END();
}

/* ----------------------------------------
 * storage_full
 */

static int v_matchproto_(objgetspace_f)
vtcstv_full_getspace(struct worker *wrk, struct objcore *oc, ssize_t *sz,
    uint8_t **ptr)
{
	(void)wrk;
	(void)oc;
	(void)sz;
	(void)ptr;

	return (0);
}

static int v_matchproto_(storage_allocobj_f)
vtcstv_full_allocobj(struct worker *wrk, const struct stevedore *stv,
    struct objcore *oc, unsigned len)
{
	(void)wrk;
	(void)stv;
	(void)oc;
	(void)len;

	return (0);
}

static void * v_matchproto_(storage_allocbuf_t)
vtcstv_full_allocbuf(struct worker *wrk, const struct stevedore *stv, size_t size,
    uintptr_t *ppriv)
{
	(void)wrk;
	(void)stv;
	(void)size;
	(void)ppriv;
	return (NULL);
}

VCL_VOID
vmod_storage_full(VRT_CTX, VCL_STEVEDORE stv)
{
	struct stevedore *wstv;
	struct obj_methods *wom;
	struct stvi *si;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);

	si = stvi_get(stv);
	AN(si);

	PATCH_BEGIN(si, stv, wstv, wom);
	wom->objgetspace = vtcstv_full_getspace;
	wstv->allocobj = vtcstv_full_allocobj;
	wstv->allocbuf = vtcstv_full_allocbuf;
	PATCH_END();
}

/* ----------------------------------------
 * storage_lessspace
 */

/* returns one byte less than requested */
static int v_matchproto_(objgetspace_f)
vtcstv_lessspace_getspace(struct worker *wrk, struct objcore *oc, ssize_t *sz,
    uint8_t **ptr)
{
	struct stvi *si;
	ssize_t less;

	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	si = stvi_get(oc->stobj->stevedore);
	AN(si);

	AN(sz);
	less = (*sz > 2) ? *sz - 1 : *sz;
	VSLb(wrk->vsl, SLT_Debug, "vtc.storage_lessspace: want %zd give %zd",
	    *sz, less);
	*sz = less;
	return (si->om_save.objgetspace(wrk, oc, sz, ptr));
}

VCL_VOID
vmod_storage_lessspace(VRT_CTX, VCL_STEVEDORE stv)
{
	struct stevedore *wstv;
	struct obj_methods *wom;
	struct stvi *si;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);

	si = stvi_get(stv);
	AN(si);

	PATCH_BEGIN(si, stv, wstv, wom);
	wom->objgetspace = vtcstv_lessspace_getspace;
	PATCH_END();
}

/* ----------------------------------------
 * storage_maxspace
 */

static void v_matchproto_(objfree_f)
vtcstv_obji_objfree(struct worker *wrk, struct objcore *oc)
{
	struct stvi *si;

	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	si = stvi_find(oc->stobj->stevedore);
	AN(si);

	obji_free(oc);
	si->om_save.objfree(wrk, oc);
}

static int v_matchproto_(storage_allocobj_f)
vtcstv_maxspace_allocobj(struct worker *wrk, const struct stevedore *stv,
    struct objcore *oc, unsigned len)
{
	struct stvi *si;
	struct obji *oi;

	CHECK_OBJ_NOTNULL(oc, OBJCORE_MAGIC);
	si = stvi_get(stv);
	AN(si);

	oi = obji_get(oc);
	AN(oi);
	oi->canalloc = si->param.maxspace;

	return (si->stv_save.allocobj(wrk, stv, oc, len));
}

static int v_matchproto_(objgetspace_f)
vtcstv_maxspace_getspace(struct worker *wrk, struct objcore *oc, ssize_t *sz,
    uint8_t **ptr)
{
	struct stvi *si;
	struct obji *oi;
	int r;

	AN(sz);

	si = stvi_get(oc->stobj->stevedore);
	AN(si);
	oi = obji_get(oc);
	AN(oi);

	VSLb(wrk->vsl, SLT_Debug, "vtc.storage_maxspace: want %zd canalloc %zd",
	    *sz, oi->canalloc);

	assert(oi->canalloc >= 0);
	if (oi->canalloc == 0)
		return (0);

	*sz = vmin_t(ssize_t, *sz, oi->canalloc);

	r = si->om_save.objgetspace(wrk, oc, sz, ptr);
	return (r);
}

static void v_matchproto_(objextend_f)
vtcstv_maxspace_extend(struct worker *wrk, struct objcore *oc, ssize_t l)
{
	struct stvi *si;
	struct obji *oi;

	si = stvi_get(oc->stobj->stevedore);
	AN(si);
	oi = obji_get(oc);
	AN(oi);

	VSLb(wrk->vsl, SLT_Debug, "vtc.storage_maxspace: extend %zd canalloc %zd",
	    l, oi->canalloc);

	if (l > oi->canalloc)
		oi->canalloc = 0;
	else
		oi->canalloc -= l;

	assert(l > 0);
	oc->stobj->priv2 += (uint64_t)l;
	si->om_save.objextend(wrk, oc, l);
}

VCL_VOID
vmod_storage_maxspace(VRT_CTX, VCL_STEVEDORE stv, VCL_BYTES b)
{
	struct stevedore *wstv;
	struct obj_methods *wom;
	struct stvi *si;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);

	if (b <= 0) {
		VRT_fail(ctx, "storage_maxspace: BYTES must be positive");
		return;
	}

	si = stvi_get(stv);
	AN(si);
	si->param.maxspace = b;

	PATCH_BEGIN(si, stv, wstv, wom);
	wom->objfree = vtcstv_obji_objfree;
	wom->objgetspace = vtcstv_maxspace_getspace;
	wom->objextend = vtcstv_maxspace_extend;
	wstv->allocobj = vtcstv_maxspace_allocobj;
	PATCH_END();
}

/* ----------------------------------------
 * storage_frag
 */
static int v_matchproto_(objgetspace_f)
vtcstv_frag_getspace(struct worker *wrk, struct objcore *oc, ssize_t *sz,
    uint8_t **ptr)
{
	struct stvi *si;
	int r;

	AN(sz);

	si = stvi_get(oc->stobj->stevedore);
	AN(si);

	VSLb(wrk->vsl, SLT_Debug, "vtc.storage_frag: want %zd frag %zd",
	    *sz, si->param.frag);

	*sz = si->param.frag;

	r = si->om_save.objgetspace(wrk, oc, sz, ptr);
	return (r);
}

VCL_VOID
vmod_storage_frag(VRT_CTX, VCL_STEVEDORE stv, VCL_BYTES b)
{
	struct stevedore *wstv;
	struct obj_methods *wom;
	struct stvi *si;

	CHECK_OBJ_NOTNULL(ctx, VRT_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(stv, STEVEDORE_MAGIC);

	if (b <= 0) {
		VRT_fail(ctx, "storage_frag: BYTES must be postive");
		return;
	}

	si = stvi_get(stv);
	AN(si);
	si->param.frag = b;

	PATCH_BEGIN(si, stv, wstv, wom);
	wom->objgetspace = vtcstv_frag_getspace;
	PATCH_END();
}
