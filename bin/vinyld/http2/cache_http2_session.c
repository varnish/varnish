/*-
 * Copyright (c) 2016 Varnish Software AS
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
 */

#include "config.h"

#include <poll.h>
#include <stdio.h>

#include "cache/cache_vinyld.h"
#include "cache/cache_transport.h"
#include "http2/cache_http2.h"

#include "tls/cache_tls.h"
#include "vend.h"
#include "vtcp.h"

static const char H2_prism[24] = {
	0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54,
	0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
	0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a
};

static size_t
h2_enc_settings(const struct h2_settings *h2s, uint8_t *buf, ssize_t n)
{
	uint8_t *p = buf;

#define H2_SETTING(U,l,v,d,...)				\
	if (h2s->l != d) {				\
		n -= 6;					\
		assert(n >= 0);				\
		vbe16enc(p, v);				\
		p += 2;					\
		vbe32enc(p, h2s->l);			\
		p += 4;					\
	}
#include "tbl/h2_settings.h"
	return (p - buf);
}

static const struct h2_settings H2_proto_settings = {
#define H2_SETTING(U,l,v,d,...) . l = d,
#include "tbl/h2_settings.h"
};

static void
h2_local_settings(struct h2_settings *h2s)
{
	*h2s = H2_proto_settings;
#define H2_SETTINGS_PARAM_ONLY
#define H2_SETTING(U, l, ...)			\
	h2s->l = cache_param->h2_##l;
#include "tbl/h2_settings.h"
#undef H2_SETTINGS_PARAM_ONLY
	h2s->max_header_list_size = cache_param->http_req_size;
}

/**********************************************************************/

static void
h2_del_sess(struct worker *wrk, struct h2_sess *h2, stream_close_t reason)
{
	struct sess *sp;
	struct req *req;

	CHECK_OBJ_NOTNULL(h2, H2_SESS_MAGIC);
	AZ(h2->refcnt);
	assert(VTAILQ_EMPTY(&h2->streams));
	AN(reason);

	VHT_Fini(h2->dectbl);
	if (h2->efd->poll_fd >= 0)
		VEFD_Close(h2->efd);
	TAKE_OBJ_NOTNULL(req, &h2->srq, REQ_MAGIC);
	assert(!WS_IsReserved(req->ws));
	TAKE_OBJ_NOTNULL(sp, &h2->sess, SESS_MAGIC);
	THR_SetRequest(NULL);
	Req_Cleanup(sp, wrk, req);
	Req_Release(req);
	SES_Delete(sp, reason, NAN);
}

/**********************************************************************
 * The h2_sess struct needs many of the same things as a request,
 * WS, VSL, HTC &c,  but rather than implement all that stuff over, we
 * grab an actual struct req, and mirror the relevant fields into
 * struct h2_sess.
 */

static struct h2_sess *
h2_init_sess(struct worker *wrk, struct sess *sp, struct h2_sess *h2s,
    struct req **psrq, struct h2h_decode *decode)
{
	struct req *srq;
	uintptr_t *up;
	struct h2_sess *h2;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	TAKE_OBJ_NOTNULL(srq, psrq, REQ_MAGIC);
	AZ(srq->ws_req);

	/* proto_priv session attribute will always have been set up by H1
	 * before reaching here. */
	AZ(SES_Get_proto_priv(sp, &up));
	assert(*up == 0);

	h2 = h2s;
	AN(h2);
	INIT_OBJ(h2, H2_SESS_MAGIC);
	h2->srq = srq;
	h2->htc = srq->htc;
	h2->ws = srq->ws;
	h2->vsl = srq->vsl;
	VSL_Flush(h2->vsl, 0);
	h2->vsl->wid = sp->vxid;
	h2->htc->rfd = &sp->fd;
	h2->sess = sp;
	h2->rxthr = pthread_self();
	VTAILQ_INIT(&h2->streams);
	h2_local_settings(&h2->local_settings);
	h2->remote_settings = H2_proto_settings;
	h2->decode = decode;
	h2->expect_settings_next = 1;
	VEFD_INIT(h2->efd);

	h2->tx_window = h2->remote_settings.initial_window_size;
	h2->rx_window = h2->local_settings.initial_window_size;

	h2->t_win_low = 0.;

	h2->rapid_reset = cache_param->h2_rapid_reset;
	h2->rapid_reset_limit = cache_param->h2_rapid_reset_limit;
	h2->rapid_reset_period = cache_param->h2_rapid_reset_period;

	h2->rst_budget = h2->rapid_reset_limit;
	h2->last_rst = sp->t_open;
	AZ(isnan(h2->last_rst));

	AZ(VHT_Init(h2->dectbl, h2->local_settings.header_table_size));

	/* Allocate a scratch space to use for staging small outgoing
	 * frames. */
	h2->tx_s_start = WS_Alloc(wrk->aws, H2_TX_BUFSIZE);
	if (h2->tx_s_start == NULL) {
		VSLb(h2->vsl, SLT_Error, "H2 sess: Out of workspace_thread");
		h2_del_sess(wrk, h2, SC_OVERLOAD);
		return (NULL);
	}
	h2->tx_s_end = h2->tx_s_start + H2_TX_BUFSIZE;
	h2->tx_s_head = h2->tx_s_start;
	h2->tx_s_mark = h2->tx_s_start;

	/* Init send queue */
	VTAILQ_INIT(&h2->tx_l_queue);

	*up = (uintptr_t)h2;

	return (h2);
}

/**********************************************************************/

enum htc_status_e v_matchproto_(htc_complete_f)
H2_prism_complete(struct http_conn *htc)
{
	size_t sz;

	CHECK_OBJ_NOTNULL(htc, HTTP_CONN_MAGIC);
	sz = sizeof(H2_prism);
	if (htc->rxbuf_b + sz > htc->rxbuf_e)
		sz = htc->rxbuf_e - htc->rxbuf_b;
	if (memcmp(htc->rxbuf_b, H2_prism, sz))
		return (HTC_S_JUNK);
	return (sz == sizeof(H2_prism) ? HTC_S_COMPLETE : HTC_S_MORE);
}


/**********************************************************************
 */

void
H2_PU_Sess(struct worker *wrk, struct sess *sp, struct req *req)
{
	VSL(SLT_Debug, sp->vxid, "H2 Prior Knowledge Upgrade");
	SES_SetTransport(wrk, sp, req, &HTTP2_transport);
}

static void v_matchproto_(task_func_t)
h2_new_session(struct worker *wrk, void *arg)
{
	struct req *srq;
	struct sess *sp;
	struct h2_sess h2s;
	struct h2_sess *h2;
	uint8_t settings[48];
	struct h2h_decode decode;
	stream_close_t reason;
	size_t l;

	/* Prior knowledge. The incoming req does not hold
	 * anything of value and can be repurposed as the session
	 * req (srq). */
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CAST_OBJ_NOTNULL(srq, arg, REQ_MAGIC);
	sp = srq->sp;
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	if (wrk->wpriv->vcl)
		VCL_Rel(&wrk->wpriv->vcl);

	assert(srq->transport == &HTTP2_transport);

	THR_SetRequest(srq);

	h2 = h2_init_sess(wrk, sp, &h2s, &srq, &decode);
	if (h2 == NULL) {
		wrk->vsl = NULL;
		return;
	}
	AZ(srq);

	CHECK_OBJ_NOTNULL(h2->htc, HTTP_CONN_MAGIC);
	AZ(h2->htc->priv);
	h2->htc->priv = h2;

	/* Set up the eventfd for communication with request handling
	 * threads. */
	if (VEFD_Open(h2->efd) < 0) {
		VSLb(h2->vsl, SLT_Error, "H2: Failed to create eventfd");
		h2_del_sess(wrk, h2, SC_OVERLOAD);
		wrk->vsl = NULL;
		return;
	}

	AZ(wrk->vsl);
	wrk->vsl = h2->vsl;

	if (sp->tls != NULL) {
		/* Hand the TLS bits a relevant VSL to write to */
		VTLS_vsl_set(sp->tls, h2->vsl);

		/* Release the writev-buffer if we are holding it */
		VTLS_buf_release(sp->tls);
	}

	VSLb(h2->vsl, SLT_Debug, "H2: Got pu PRISM");

	assert(HTC_S_COMPLETE == H2_prism_complete(h2->htc));

	/* Initialize the workspace rx buffer. Some read overshoot data
	 * may be present as pipeline data. This sequence of calls
	 * basically just resets the WS, memmove()s the pipeline data
	 * first, and sets htc->rxbuf_[be] to the pipeline data. */
	HTC_RxPipeline(h2->htc, h2->htc->rxbuf_b + sizeof(H2_prism));
	WS_Rollback(h2->ws, 0);
	HTC_RxInit(h2->htc, h2->ws);
	WS_ReleaseP(h2->htc->ws, h2->htc->rxbuf_e);

	/* Send our settings */
	l = h2_enc_settings(&h2->local_settings, settings, sizeof (settings));
	H2_Send_SETTINGS(h2, H2FF_NONE, l, settings);

	/* and off we go... */
	h2_run(wrk, h2);

	assert(!WS_IsReserved(h2->ws));
	AN(h2->error);
	reason = h2->error->reason;
	if (reason == SC_NULL) {
		/* XXX: It's messy that some h2_errors have reasosn
		 * SC_NULL, which is just WRONG() wrt to SES_Delete(). */
		reason = SC_REM_CLOSE;
	}
	h2_del_sess(wrk, h2, reason);
	wrk->vsl = NULL;
}

static int v_matchproto_(vtr_poll_f)
h2_poll(struct req *req)
{
	struct h2_req *r2;

	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	CAST_OBJ_NOTNULL(r2, req->transport_priv, H2_REQ_MAGIC);
	return (r2->error ? -1 : 1);
}

struct transport HTTP2_transport = {
	.name =			"HTTP/2",
	.magic =		TRANSPORT_MAGIC,
	.deliver =		h2_deliver,
	.minimal_response =	h2_minimal_response,
	.new_session =		h2_new_session,
	.req_body =		h2_reqbody,
	.req_fail =		h2_req_fail,
	.sess_panic =		h2_sess_panic,
	.poll =			h2_poll,
};
