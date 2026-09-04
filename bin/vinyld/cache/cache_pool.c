/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
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
 * We maintain a number of worker thread pools, to spread lock contention.
 *
 * Pools can be added on the fly, as a means to mitigate lock contention,
 * but can only be removed again by a restart. (XXX: we could fix that)
 *
 */

#include "config.h"

#include <stdlib.h>

#include "cache_int.h"
#include "cache_pool.h"

#include "vtim.h"

static pthread_t		thr_pool_herder;

static struct lock		wstat_mtx;
struct lock			pool_mtx;
static VTAILQ_HEAD(,pool)	pools = VTAILQ_HEAD_INITIALIZER(pools);
static pthread_cond_t		cond = PTHREAD_COND_INITIALIZER;

/*--------------------------------------------------------------------
 * Summing of stats into global stats counters
 */

void
Pool_Sumstat(const struct worker *wrk)
{

	Lck_Lock(&wstat_mtx);
	VSC_main_Summ_wrk(VSC_C_main, wrk->stats);
	Lck_Unlock(&wstat_mtx);
	memset(wrk->stats, 0, sizeof *wrk->stats);
}

int
Pool_TrySumstat(const struct worker *wrk)
{
	if (Lck_Trylock(&wstat_mtx))
		return (0);
	VSC_main_Summ_wrk(VSC_C_main, wrk->stats);
	Lck_Unlock(&wstat_mtx);
	memset(wrk->stats, 0, sizeof *wrk->stats);
	return (1);
}

/*--------------------------------------------------------------------
 * Facility for scheduling a task on any convenient pool.
 */

int
Pool_Task_Any(struct pool_task *task, enum task_prio prio)
{
	struct pool *pp;

	Lck_Lock(&pool_mtx);
	pp = VTAILQ_FIRST(&pools);
	if (pp != NULL) {
		VTAILQ_REMOVE(&pools, pp, list);
		VTAILQ_INSERT_TAIL(&pools, pp, list);
		AZ(pp->die);
	}
	Lck_Unlock(&pool_mtx);
	if (pp == NULL)
		return (-1);

	// We never see a dying pool here, but it might die right after the
	// Unlock, in which case Pool_Task races for a worker, but because of
	// the destruction delay it is highly unlikely that all threads are gone

	return (Pool_Task(pp, task, prio));
}

/*--------------------------------------------------------------------
 * Helper function to update stats for purges under lock
 */

void
Pool_PurgeStat(unsigned nobj)
{
	Lck_Lock(&wstat_mtx);
	VSC_C_main->n_purges++;
	VSC_C_main->n_obj_purged += nobj;
	Lck_Unlock(&wstat_mtx);
}

/*--------------------------------------------------------------------
 * Special function to summ stats
 */

void v_matchproto_(task_func_t)
pool_stat_summ(struct worker *wrk, void *priv)
{
	struct VSC_main_wrk *src;
	struct pool *pp;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	pp = wrk->pool;
	CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);
	AN(priv);
	src = priv;

	Lck_Lock(&wstat_mtx);
	VSC_main_Summ_wrk(VSC_C_main, src);

	Lck_Lock(&pp->mtx);
	VSC_main_Summ_pool(VSC_C_main, pp->stats);
	Lck_Unlock(&pp->mtx);
	memset(pp->stats, 0, sizeof pp->stats);

	Lck_Unlock(&wstat_mtx);
	memset(src, 0, sizeof *src);

	AZ(pp->b_stat);
	pp->b_stat = src;
}

/*--------------------------------------------------------------------
 * Add a thread pool
 */

static struct pool *
pool_mkpool(unsigned pool_no)
{
	struct pool *pp;
	int i;

	ALLOC_OBJ(pp, POOL_MAGIC);
	if (pp == NULL)
		return (NULL);
	pp->a_stat = calloc(1, sizeof *pp->a_stat);
	AN(pp->a_stat);
	pp->b_stat = calloc(1, sizeof *pp->b_stat);
	AN(pp->b_stat);
	Lck_New(&pp->mtx, lck_perpool);

	VTAILQ_INIT(&pp->idle_queue);
	VTAILQ_INIT(&pp->poolsocks);
	for (i = 0; i < TASK_QUEUE_RESERVE; i++)
		VTAILQ_INIT(&pp->queues[i]);
	PTOK(pthread_cond_init(&pp->herder_cond, NULL));
	PTOK(pthread_create(&pp->herder_thr, NULL, pool_herder, pp));

	while (VTAILQ_EMPTY(&pp->idle_queue))
		VTIM_sleep(0.01);

	SES_NewPool(pp, pool_no);
	VCA_NewPool(pp);

	return (pp);
}

static void
pool_destroy(struct pool *ppx)
{
	void *rvp;

	CHECK_OBJ_NOTNULL(ppx, POOL_MAGIC);
	PTOK(pthread_join(ppx->herder_thr, &rvp));
	PTOK(pthread_cond_destroy(&ppx->herder_cond));
	assert(VTAILQ_EMPTY(&ppx->poolsocks));
	free(ppx->a_stat);
	free(ppx->b_stat);
	SES_DestroyPool(ppx);
	Lck_Delete(&ppx->mtx);
	FREE_OBJ(ppx);
	VSC_C_main->pools--;
}

/*--------------------------------------------------------------------
 * This thread adjusts the number of pools to match the parameter.
 *
 * NB: This is quite silly.  The master should tell the child through
 * NB: CLI when parameters change and an appropriate call-out table
 * NB: be maintained for params which require action.
 */

static void * v_matchproto_()
pool_poolherder(void *priv)
{
	VTAILQ_HEAD(,pool) deadpools = VTAILQ_HEAD_INITIALIZER(deadpools);
	unsigned nwq, poolno;
	struct pool *pp;
	uint64_t u;

	THR_SetName("pool_poolherder");
	THR_Init();
	(void)priv;

	nwq = poolno = 0;
	while (cache_param->wthread_pools > 0 ||
	    VTAILQ_FIRST(&pools) ||
	    VTAILQ_FIRST(&deadpools)) {
		if (nwq < cache_param->wthread_pools) {
			// die before we would wrap
			assert(poolno < UINT_MAX);
			pp = pool_mkpool(poolno);
			if (pp != NULL) {
				Lck_Lock(&pool_mtx);
				VTAILQ_INSERT_TAIL(&pools, pp, list);
				Lck_Unlock(&pool_mtx);
				VSC_C_main->pools++;
				poolno++;
				nwq++;
				continue;
			}
		} else if (nwq > cache_param->wthread_pools) {
			Lck_Lock(&pool_mtx);
			pp = VTAILQ_FIRST(&pools);
			CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);
			VTAILQ_REMOVE(&pools, pp, list);
			AZ(pp->die);
			Lck_Unlock(&pool_mtx);

			VTAILQ_INSERT_TAIL(&deadpools, pp, list);
			AN(nwq);
			nwq--;
			VSL(SLT_Debug, NO_VXID, "Kill Pool %p", pp);
			pp->die = 1;
			VCA_DestroyPool(pp);
			PTOK(pthread_cond_signal(&pp->herder_cond));
			continue;
		}

		while ((pp = VTAILQ_FIRST(&deadpools)) != NULL) {
			CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);
			int active;

			AN(pp->die);
			if (pp->nthr > 0 || pp->wrk_dying > 0)
				continue;

			Lck_Lock(&pp->mtx);
			active = (pp->nthr > 0 || pp->wrk_dying > 0) ? 1 : 0;
			Lck_Unlock(&pp->mtx);

			if (active)
				 continue;

			VTAILQ_REMOVE(&deadpools, pp, list);
			pool_destroy(pp);
		}

		u = 0;
		Lck_Lock(&pool_mtx);
		VTAILQ_FOREACH(pp, &pools, list) {
			CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);

			u += pp->lqueue;
		}
		VSC_C_main->thread_queue_len = u;
		if (nwq > 0 || cache_param->wthread_pools > 0)
			(void)Lck_CondWaitTimeout(&cond, &pool_mtx, 1.0);
		Lck_Unlock(&pool_mtx);
	}
	return (NULL);
}

/*--------------------------------------------------------------------*/
void
pan_pool(struct vsb *vsb)
{
	struct pool *pp;

	VSB_cat(vsb, "pools = {\n");
	VSB_indent(vsb, 2);
	VTAILQ_FOREACH(pp, &pools, list) {
		if (PAN_dump_struct(vsb, pp, POOL_MAGIC, "pool"))
			continue;
		VSB_printf(vsb, "nidle = %u,\n", pp->nidle);
		VSB_printf(vsb, "nthr = %u,\n", pp->nthr);
		VSB_printf(vsb, "lqueue = %u\n", pp->lqueue);
		VSB_indent(vsb, -2);
		VSB_cat(vsb, "},\n");
	}
	VSB_indent(vsb, -2);
	VSB_cat(vsb, "},\n");
}

/*--------------------------------------------------------------------*/

void
Pool_Init(void)
{

	Lck_New(&wstat_mtx, lck_wstat);
	Lck_New(&pool_mtx, lck_wq);
	PTOK(pthread_create(&thr_pool_herder, NULL, pool_poolherder, NULL));
	while (!VSC_C_main->pools)
		VTIM_sleep(0.01);
}

void
Pool_Stop(void)
{
	Lck_Lock(&pool_mtx);
	cache_param->wthread_pools = 0;
	PTOK(pthread_cond_signal(&cond));
	Lck_Unlock(&pool_mtx);
}

void
Pool_Fini(void)
{
	AZ(pthread_join(thr_pool_herder, NULL));
}
