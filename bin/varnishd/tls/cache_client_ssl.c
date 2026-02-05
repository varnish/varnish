/*-
 * Copyright (c) 2019-2026 Varnish Software AS
 * All rights reserved.
 *
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
 * Author: Niklas Brand <niklasb@varnish-software.com>
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
 * Client-side TLS termination
 */

#include "config.h"

#include <openssl/dh.h>
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <stdlib.h>

#include "common/common_vtls_types.h"
#include "cache/cache_varnishd.h"
#include "cache/cache_conn_oper.h"
#include "cache/cache_pool.h"
#include "vcli_serve.h"
#include "cache_tls.h"

#include "cache/cache_transport.h"
#include "common/heritage.h"

#include "vend.h"
#include "vqueue.h"
#include "vsb.h"
#include "vtcp.h"
#include "vtim.h"
#include "vtree.h"

#include "cache_client_ssl.h"

VTAILQ_HEAD(v_ctx_list, vtls_ctx);

struct vtls_sni_map;
VRBT_HEAD(vtls_sni_rbtree, vtls_sni_key);
VRBT_PROTOTYPE(vtls_sni_rbtree, vtls_sni_key, tree, vtls_sni_key_cmp);

static int vtls_sni_key_cmp(const struct vtls_sni_key *a,
    const struct vtls_sni_key *b);

struct vtls_sni_map {
	unsigned			magic;
#define VTLS_SNI_MAP_MAGIC		0x15335fe1
	struct vtls_sni_rbtree		root;
	VTAILQ_ENTRY(vtls_sni_map)	list;
};

VRBT_GENERATE(vtls_sni_rbtree, vtls_sni_key, tree, vtls_sni_key_cmp);

/*
 * Cleanup task for deferred freeing of SSL_CTX objects.
 * This provides a "cooling period" to avoid use-after-free races
 * when a certificate is discarded while handshakes are in progress.
 */
struct vtls_cleanup_task {
	unsigned			magic;
#define VTLS_CLEANUP_MAGIC		0xe01f014c
	vtim_mono			cooled;
	struct v_ctx_list		*ctxs;
	VTAILQ_HEAD(, vtls_sni_map)	sni_maps;
	VTAILQ_ENTRY(vtls_cleanup_task)	list;
};

static VTAILQ_HEAD(, vtls_cleanup_task)	cleanup_tasks =
    VTAILQ_HEAD_INITIALIZER(cleanup_tasks);

struct vtls_options {
	int protos;
	int prefer_server_ciphers;
	int is_default;
	char *cert_key;
	char *key;
	char *dh;
	const char *id;
	const char *fe;
	const char *ciphers;
	const char *ciphersuites;
	const char *sni_list;
};

void
VTLS_del_sess(struct pool *pp, struct vtls_sess **ptsp)
{
	struct vtls_sess *tsp;

	CHECK_OBJ_NOTNULL(pp, POOL_MAGIC);
	TAKE_OBJ_NOTNULL(tsp, ptsp, VTLS_SESS_MAGIC);

	free(tsp->ja3);

	if (tsp->buf != NULL)
		VTLS_buf_free(&tsp->buf);
	if (tsp->ssl)
		SSL_free(tsp->ssl);
	FREE_OBJ(tsp);
}

void
VTLS_vsl_set(struct vtls_sess *tsp, struct vsl_log *vsl)
{
	CHECK_OBJ_ORNULL(tsp, VTLS_SESS_MAGIC);
	if (tsp == NULL)
		return;

	tsp->log->vsl = vsl;
}

static int
vtls_sni_key_cmp(const struct vtls_sni_key *a,
    const struct vtls_sni_key *b)
{
	AN(a->id);
	AN(b->id);
	return (strcasecmp(a->id, b->id));
}

static struct vtls_sni_map *
vtls_sni_map_new(void)
{
	struct vtls_sni_map *m;

	ALLOC_OBJ(m, VTLS_SNI_MAP_MAGIC);
	AN(m);
	VRBT_INIT(&m->root);
	return (m);
}

static void
vtls_sni_key_free(struct vtls_sni_key *k)
{
	CHECK_OBJ_ORNULL(k, VTLS_SNI_KEY_MAGIC);
	if (k) {
		free(k->id);
		FREE_OBJ(k);
	}
}

static struct vtls_sni_key *
vtls_sni_key_alloc(const char *id, unsigned is_wildcard, struct vtls_ctx *ctx)
{
	struct vtls_sni_key *k;

	ALLOC_OBJ(k, VTLS_SNI_KEY_MAGIC);
	AN(k);

	REPLACE(k->id, id);
	k->is_wildcard = is_wildcard;
	k->ctx = ctx;
	VTAILQ_INIT(&k->dups);

	return (k);
}

static int
vtls_sni_map_add(struct vtls_sni_map *m, char *id,
    struct vtls_ctx *ctx)
{
	struct vtls_sni_key *k, *r;
	unsigned is_wildcard = 0;

	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
	AN(id);

	if (strstr(id, "*.") == id) {
		is_wildcard = 1;
		id++;
	}
	k = vtls_sni_key_alloc(id, is_wildcard, ctx);

	r = VRBT_INSERT(vtls_sni_rbtree, &m->root, k);
	if (r) {
		/* duplicate: New cert takes precedence */
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		VRBT_REMOVE(vtls_sni_rbtree, &m->root, r);
		VTAILQ_CONCAT(&k->dups, &r->dups, dups_list);
		VTAILQ_INSERT_HEAD(&k->dups, r, dups_list);
		AZ(VRBT_INSERT(vtls_sni_rbtree, &m->root, k));
	}

	return (0);
}

static struct vtls_ctx *
_vtls_sni_lookup(const struct vtls_sni_map *m, const char *id, int wc)
{
	struct vtls_sni_key k, *r;

	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
	INIT_OBJ(&k, VTLS_SNI_KEY_MAGIC);
	k.id = TRUST_ME(id);

	r = VRBT_FIND(vtls_sni_rbtree, &m->root, &k);
	if (r) {
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		return (r->ctx);
	} else if (!wc)
		return (NULL);

	/* Do another lookup for wildcard matches */
	k.id = strchr(id, '.');
	if (k.id == NULL)
		return (NULL);
	r = VRBT_FIND(vtls_sni_rbtree, &m->root, &k);
	if (r) {
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		if (!r->is_wildcard)
			return (NULL);
		return (r->ctx);
	}

	return (NULL);
}

/*
 * Check if a hostname already exists in the SNI map
 */
static int
vtls_sni_exists(const struct vtls_sni_map *m, const char *id)
{
	struct vtls_sni_key k, *r;

	if (m == NULL)
		return (0);
	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);

	INIT_OBJ(&k, VTLS_SNI_KEY_MAGIC);

	/* Strip wildcard prefix for lookup */
	if (strstr(id, "*.") == id)
		id++;
	k.id = TRUST_ME(id);

	r = VRBT_FIND(vtls_sni_rbtree, &m->root, &k);
	if (r != NULL) {
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		if (!r->ctx->discarded)
			return (1);
	}
	return (0);
}

/*
 * Free all entries in an SNI map
 */
static void
vtls_sni_map_free(struct vtls_sni_map **pm)
{
	struct vtls_sni_map *m;
	struct vtls_sni_key *k, *k_tmp;
	struct vtls_sni_key *dup, *dup_tmp;

	AN(pm);
	if (*pm == NULL)
		return;

	TAKE_OBJ_NOTNULL(m, pm, VTLS_SNI_MAP_MAGIC);

	VRBT_FOREACH_SAFE(k, vtls_sni_rbtree, &m->root, k_tmp) {
		VRBT_REMOVE(vtls_sni_rbtree, &m->root, k);
		VTAILQ_FOREACH_SAFE(dup, &k->dups, dups_list, dup_tmp) {
			VTAILQ_REMOVE(&k->dups, dup, dups_list);
			vtls_sni_key_free(dup);
		}
		vtls_sni_key_free(k);
	}
	FREE_OBJ(m);
}

/*
 * Copy an SNI key entry to another map (used during commit)
 */
static void
vtls_sni_map_add_copy(struct vtls_sni_map *m, struct vtls_sni_key *src)
{
	struct vtls_sni_key *k, *r;

	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
	CHECK_OBJ_NOTNULL(src, VTLS_SNI_KEY_MAGIC);

	k = vtls_sni_key_alloc(src->id, src->is_wildcard, src->ctx);

	r = VRBT_INSERT(vtls_sni_rbtree, &m->root, k);
	if (r) {
		/* Duplicate: add to existing entry's dups list */
		CHECK_OBJ_NOTNULL(r, VTLS_SNI_KEY_MAGIC);
		VTAILQ_INSERT_TAIL(&r->dups, k, dups_list);
	}
}

/*
 * Remove all SNI entries for a given vtls_ctx from the map
 */
static void
vtls_sni_map_remove_ctx(struct vtls_sni_map *m, struct vtls_ctx *ctx)
{
	struct vtls_sni_key *k, *k_tmp;
	struct vtls_sni_key *dup, *dup_tmp;

	if (m == NULL)
		return;
	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
	CHECK_OBJ_NOTNULL(ctx, VTLS_CTX_MAGIC);

	VRBT_FOREACH_SAFE(k, vtls_sni_rbtree, &m->root, k_tmp) {
		if (k->ctx == ctx) {
			VRBT_REMOVE(vtls_sni_rbtree, &m->root, k);
			VTAILQ_FOREACH_SAFE(dup, &k->dups, dups_list, dup_tmp) {
				VTAILQ_REMOVE(&k->dups, dup, dups_list);
				vtls_sni_key_free(dup);
			}
			vtls_sni_key_free(k);
		} else {
			/* Check duplicates list */
			VTAILQ_FOREACH_SAFE(dup, &k->dups, dups_list, dup_tmp) {
				if (dup->ctx == ctx) {
					VTAILQ_REMOVE(&k->dups, dup, dups_list);
					vtls_sni_key_free(dup);
				}
			}
		}
	}
}

/*
 * Extract hostnames from X509 certificate and add to SNI map
 * Extracts Subject Alternative Names (DNS type) or falls back to Common Name
 */
static int
vtls_load_x509_names(struct cli *cli, struct vtls *vtls,
    struct vtls_ctx *vc, X509 *x509)
{
	STACK_OF(GENERAL_NAME) *names;
	char *p;
	int i, nb = 0, nf = 0, err = 0;

	CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);
	CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);
	CHECK_OBJ_NOTNULL(vtls->sni_scratch, VTLS_SNI_MAP_MAGIC);

	/* Extract CN for display purposes */
	{
		X509_NAME *x509_name;
		X509_NAME_ENTRY *x509_entry;

		x509_name = X509_get_subject_name(x509);
		if (x509_name != NULL) {
			i = X509_NAME_get_index_by_NID(x509_name,
			    NID_commonName, -1);
			if (i >= 0) {
				x509_entry = X509_NAME_get_entry(x509_name, i);
				if (x509_entry != NULL) {
					ASN1_STRING_to_UTF8((unsigned char **)&p,
					    X509_NAME_ENTRY_get_data(x509_entry));
					if (p != NULL) {
						vc->subject = strdup(p);
						AN(vc->subject);
						OPENSSL_free(p);
					}
				}
			}
		}
	}

/*
 * nb = number of names added to SNI map
 * nf = number of names found in certificate (including duplicates)
 * err = number of duplicate errors (when tls_err_dup_servername is set)
 */
#define ADD_TO_SNI(name)						\
do {									\
	nf++;								\
	if (cache_param->tls_err_dup_servername &&			\
	    vtls_sni_exists(vtls->sni, name)) {				\
		VCLI_Out(cli, "'%s' already loaded.\n", name);		\
		err++;							\
	} else if (cache_param->tls_err_dup_servername &&		\
	    vtls_sni_exists(vtls->sni_scratch, name)) {			\
		VCLI_Out(cli, "'%s' already staged.\n", name);		\
		err++;							\
	} else if (vtls_sni_exists(vtls->sni_scratch, name)) {		\
		/* Duplicate in scratch, silently skip */		\
	} else {							\
		AZ(vtls_sni_map_add(vtls->sni_scratch, name, vc));	\
		nb++;							\
	}								\
} while (0)

	/* First try Subject Alternative Names */
	names = X509_get_ext_d2i(x509, NID_subject_alt_name, NULL, NULL);
	if (names != NULL) {
		for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
			GENERAL_NAME *n;
			n = sk_GENERAL_NAME_value(names, i);
			if (n->type == GEN_DNS) {
				ASN1_STRING_to_UTF8((unsigned char **)&p,
				    n->d.dNSName);
				if (p != NULL) {
					ADD_TO_SNI(p);
					OPENSSL_free(p);
				}
			}
		}
		sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
	}

	/* Fall back to Common Name if no SANs */
	if (nb == 0) {
		X509_NAME *x509_name;
		X509_NAME_ENTRY *x509_entry;

		x509_name = X509_get_subject_name(x509);
		if (x509_name != NULL) {
			i = X509_NAME_get_index_by_NID(x509_name,
			    NID_commonName, -1);
			if (i >= 0) {
				x509_entry = X509_NAME_get_entry(x509_name, i);
				if (x509_entry != NULL) {
					ASN1_STRING_to_UTF8((unsigned char **)&p,
					    X509_NAME_ENTRY_get_data(x509_entry));
					if (p != NULL) {
						ADD_TO_SNI(p);
						OPENSSL_free(p);
					}
				}
			}
		}
	}
#undef ADD_TO_SNI

	if (err > 0)
		return (-1);

	if (nf == 0) {
		VCLI_Out(cli, "Could not find valid SAN or CN in certificate\n");
		return (-1);
	}

	(void)nb;  /* nb may be 0 if all names were duplicates - that's OK */
	return (0);
}

static struct vtls_ctx *
vtls_sni_lookup(const struct vtls_sni_map *m, const char *id)
{
	return (_vtls_sni_lookup(m, id, 1));
}

static void
vtls_ctx_free(struct vtls_ctx *c)
{
	CHECK_OBJ_ORNULL(c, VTLS_CTX_MAGIC);
	if (c == NULL)
		return;

	SSL_CTX_free(c->ctx);
	free(c->name_id);
	free(c->subject);
	FREE_OBJ(c);
}

static int
vtls_alpn_select(SSL *ssl, const unsigned char **out, unsigned char *outlen,
    const unsigned char *in, unsigned int inlen, void *arg)
{
	int r;
	const unsigned char *p;
	unsigned plen;
	static const unsigned char protos_h2[] = {
		2, 'h', '2',
		8, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};

	static const unsigned char protos_h11[] = {
		8, 'h', 't', 't', 'p', '/', '1', '.', '1'
	};

	(void)arg;
	(void)ssl;

	if (FEATURE(FEATURE_HTTP2)) {
		p = protos_h2;
		plen = sizeof(protos_h2);
	} else {
		p = protos_h11;
		plen = sizeof(protos_h11);
	}

	r = SSL_select_next_proto(TRUST_ME(out), outlen, p, plen, in, inlen);
	if (r != OPENSSL_NPN_NEGOTIATED) {
		return (SSL_TLSEXT_ERR_NOACK);
	}

	return (SSL_TLSEXT_ERR_OK);
}

static void
vtls_set_protos(SSL *ssl, int protos)
{
	int proto_min, proto_max;

	AN(ssl);
	proto_min = proto_max = 0;
	if (protos == 0)
		protos = VTLS_PROTO_DEFAULT;

#define VTLS_PROTO(vtls_proto, n, ssl_proto, s) \
	if (protos & vtls_proto) {              \
		if (!proto_min)                 \
			proto_min = ssl_proto;  \
		proto_max = ssl_proto;          \
	}
#include "common/common_tls_protos.h"

	SSL_set_min_proto_version(ssl, proto_min);
	SSL_set_max_proto_version(ssl, proto_max);
}

static int
vtls_sni(const struct vtls *tls, SSL *ssl, const char *sn, int protos)
{
	struct vtls_ctx *tls_ctx = NULL;
	int result = SSL_TLSEXT_ERR_NOACK;

	CHECK_OBJ_NOTNULL(tls, VTLS_MAGIC);
	CHECK_OBJ_ORNULL(tls->sni, VTLS_SNI_MAP_MAGIC);
	CHECK_OBJ_ORNULL(heritage.tls->sni, VTLS_SNI_MAP_MAGIC);
	AN(sn);
	AN(ssl);

	if (tls->cfg->sni_nomatch_abort)
		result = SSL_TLSEXT_ERR_ALERT_FATAL;

	/* Check local list */
	if (tls->sni)
		tls_ctx = vtls_sni_lookup(tls->sni, sn);

	/* Check global certs */
	if (tls_ctx == NULL && heritage.tls->sni != NULL &&
	    tls != heritage.tls && tls->sni_match_global)
		tls_ctx = vtls_sni_lookup(heritage.tls->sni, sn);

	if (tls_ctx != NULL) {
		CHECK_OBJ_NOTNULL(tls_ctx, VTLS_CTX_MAGIC);
		if (0 != tls_ctx->protos)
			protos = tls_ctx->protos;
		SSL_set_SSL_CTX(ssl, tls_ctx->ctx);
		result = SSL_TLSEXT_ERR_OK;
	}

	vtls_set_protos(ssl, protos);

	return (result);
}

/* Parses a server name extension payload.
   The format here is defined in RFC3546, section 3.1
 */
static int
vtls_server_name_parse(const unsigned char *p, ssize_t l, struct vsb *vsb)
{
	uint16_t ll, nl;

	/* first two bytes: length of list: */
	if (l <= 2)
		return (1);
	ll = vbe16dec(p);
	p += 2;
	l -= 2;

	/* Malformed server name list */
	if (ll != l || ll == 0)
		return (1);

	/* Only the host_name name type is specified, and no clients
	 * ever send more than one so we only consider the first list
	 * entry. */

	if (*p != TLSEXT_NAMETYPE_host_name)
		return (1);
	p++;
	l--;
	/* next two bytes: length of name entry */
	if (l <= 2)
		return (1);
	nl = vbe16dec(p);
	p += 2;
	l -= 2;
	if (nl > l)
		return (1);

	/* We make a copy to ensure we get something with a
	 * null byte at the end. */
	VSB_bcat(vsb, p, nl);
	return (0);
}

#define IS_GREASE_TLS(x) \
	((((x) & 0x0f0f) == 0x0a0a) && (((x) & 0xff) == (((x) >> 8) & 0xff)))

static void
vtls_ja3_parsefields(int s, const unsigned char *data, int len,
    struct vsb *ja3)
{
	int cnt;
	uint16_t tmp;
	int first = 1;

	for (cnt = 0; cnt < len; cnt += s) {
		if (s == 1)
			tmp = *data;
		else
			tmp = vbe16dec(data);

		data += s;

		if (s != 2 || !IS_GREASE_TLS(tmp)) {
			if (!first)
				VSB_putc(ja3, '-');

			first = 0;
			VSB_printf(ja3, "%i", tmp);
		}
	}
}

static int
vtls_get_ja3(SSL *ssl, struct sess *sp, struct vtls_sess *tsp)
{
	struct vsb ja3[1];
	size_t len, i;
	const unsigned char *p;
	int first, type, *out;
	char *ja3p;
	uintptr_t sn;

	sn = WS_Snapshot(sp->ws);
	WS_VSB_new(ja3, sp->ws);
	VSB_printf(ja3, "%i,", SSL_version(ssl));

	len = SSL_client_hello_get0_ciphers(ssl, &p);
	vtls_ja3_parsefields(2, p, len, ja3);
	VSB_putc(ja3, ',');

	if (SSL_client_hello_get1_extensions_present(ssl, &out, &len) == 1) {
		first = 1;
		for (i = 0; i < len; i++) {
			type = out[i];
			if (!IS_GREASE_TLS(type)) {
				if (!first)
					VSB_putc(ja3, '-');

				first = 0;
				VSB_printf(ja3, "%i", type);
			}
		}
		OPENSSL_free(out);
	}
	VSB_putc(ja3, ',');

	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_elliptic_curves, &p,
	    &len) == 1) {
		p += 2;
		len -= 2;
		vtls_ja3_parsefields(2, p, len, ja3);
	}
	VSB_putc(ja3, ',');

	if (SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ec_point_formats, &p,
	    &len) == 1) {
		++p;
		--len;
		vtls_ja3_parsefields(1, p, len, ja3);
	}

	ja3p = WS_VSB_finish(ja3, sp->ws, NULL);
	if (ja3p == NULL) {
		VTLS_LOG(tsp->log, SLT_Error,
		    "Out of workspace_session during JA3 handling");
		return (1);
	}

	REPLACE(tsp->ja3, ja3p);
	WS_Reset(sp->ws, sn);
	return (0);
}

static int
vtls_clienthello_cb(SSL *ssl, int *al, void *priv)
{
	const struct vtls *tls;
	struct vtls_sess *tsp;
	struct sess *sp;
	size_t l;
	const unsigned char *ext;
	struct vsb vsb[1];
	char *sn;
	int err, protos;

	AN(ssl);
	CAST_OBJ_NOTNULL(sp, SSL_get_app_data(ssl), SESS_MAGIC);
	CAST_OBJ_NOTNULL(tsp, sp->tls, VTLS_SESS_MAGIC);
	CAST_OBJ_NOTNULL(tls, tsp->priv_local, VTLS_MAGIC);

	(void)al;
	(void)priv;

	protos = tls->protos;
	if (protos == 0)
		protos = heritage.tls->protos;

	if (cache_param->tls_ja3 && vtls_get_ja3(ssl, sp, tsp) != 0)
		return (SSL_CLIENT_HELLO_ERROR);

	if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name,
	    &ext, &l)) {
		tsp->sni_result = SSL_TLSEXT_ERR_NOACK;
		vtls_set_protos(ssl, protos);
		return (SSL_CLIENT_HELLO_SUCCESS);
	}

	WS_VSB_new(vsb, sp->ws);
	err = vtls_server_name_parse(ext, l, vsb);
	sn = WS_VSB_finish(vsb, sp->ws, NULL);
	if (err)
		return (SSL_CLIENT_HELLO_ERROR);
	if (sn == NULL) {
		VTLS_LOG(tsp->log, SLT_Error,
		    "Out of workspace_session during SNI handling");
		return (SSL_CLIENT_HELLO_ERROR);
	}
	tsp->sni_result = vtls_sni(tls, ssl, sn, protos);

	return (SSL_CLIENT_HELLO_SUCCESS);
}

static int
vtls_sni_cb(SSL *ssl, int *al, void *priv)
{
	struct vtls_sess *tsp;
	struct sess *sp;
	/*
	 * Even though we do the important bits in the ClientHello
	 * callback, this callback is still needed in order to
	 * acknowledge the servername request.
	 */

	(void)al;
	(void)priv;
	CAST_OBJ_NOTNULL(sp, SSL_get_app_data(ssl), SESS_MAGIC);
	CAST_OBJ_NOTNULL(tsp, sp->tls, VTLS_SESS_MAGIC);

	return (tsp->sni_result);
}

static void
vtls_sess_abandon(struct worker *wrk, struct req *req,
    struct sess *sp, stream_close_t reason)
{
	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(req, REQ_MAGIC);
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);

	Req_Cleanup(sp, wrk, req);
	Req_Release(req);
	SES_Delete(sp, reason, NAN);
}

static void v_matchproto_(task_func_t)
vtls_new_session(struct worker *wrk, void *arg)
{
	struct req *req;
	struct sess *sp;
	struct vtls *vtls_local;
	struct vtls_ctx *tls_ctx;
	struct vtls_sess *tsp;

	CHECK_OBJ_NOTNULL(wrk, WORKER_MAGIC);
	CHECK_OBJ_NOTNULL(wrk->pool, POOL_MAGIC);
	CAST_OBJ_NOTNULL(req, arg, REQ_MAGIC);
	sp = req->sp;
	CHECK_OBJ_NOTNULL(sp, SESS_MAGIC);
	CHECK_OBJ_NOTNULL(sp->listen_sock, LISTEN_SOCK_MAGIC);
	CHECK_OBJ_NOTNULL(sp->listen_sock->tls, VTLS_MAGIC);
	vtls_local = sp->listen_sock->tls;

	CHECK_OBJ_NOTNULL(heritage.tls, VTLS_MAGIC);

	ALLOC_OBJ(tsp, VTLS_SESS_MAGIC);
	AN(tsp);
	tsp->log->is_client = 1;
	tsp->log->vxid = sp->vxid;
	sp->tls = tsp;
	tsp->priv_local = vtls_local;

	if (vtls_local->d_ctx)
		tls_ctx = vtls_local->d_ctx;
	else if (heritage.tls->d_ctx)
		tls_ctx = heritage.tls->d_ctx;
	else {
		VTLS_LOG(tsp->log, SLT_TLS, "No certificates loaded");
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_BAD);
		return;
	}

	CHECK_OBJ_NOTNULL(tls_ctx, VTLS_CTX_MAGIC);

	tsp->ssl = SSL_new(tls_ctx->ctx);
	if (tsp->ssl == NULL) {
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_OVERFLOW);
		return;
	}

	if (SSL_set_app_data(tsp->ssl, sp) == 0) {
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_OVERFLOW);
		return;
	}

	VTCP_nonblocking(sp->fd);
	if (SSL_set_fd(tsp->ssl, sp->fd) == 0) {
		VTLS_vsl_ssllog(tsp->log);
		vtls_sess_abandon(wrk, req, sp, SC_RX_OVERFLOW);
		return;
	}

	SSL_set_accept_state(tsp->ssl);
	if (VTLS_do_handshake(tsp, sp->fd,
	    cache_param->tls_handshake_timeout)) {
		vtls_sess_abandon(wrk, req, sp, SC_RX_BAD);
		return;
	}

	sp->t_idle = VTIM_real();
	req->htc->oper = VTLS_conn_oper_client(tsp, &req->htc->oper_priv);
	(void)VTCP_blocking(sp->fd);
	SES_SetTransport(wrk, sp, req, &HTTP1_transport);
}

struct transport TLS_transport = {
	.name =			"TLS",
	.proto_ident =		"TLS",
	.magic =		TRANSPORT_MAGIC,
	.new_session =		vtls_new_session
};

/*
 * Base64 decode PEM data received from manager
 */
static char *
vtls_cli_base64_decode(const char *b64, int *out_len)
{
	BIO *bio, *b64bio;
	int b64_len;
	char *buf;

	AN(b64);
	AN(out_len);

	b64_len = strlen(b64);
	buf = malloc(b64_len);  /* Decoded is always smaller */
	AN(buf);

	b64bio = BIO_new(BIO_f_base64());
	AN(b64bio);
	BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);

	bio = BIO_new_mem_buf(TRUST_ME(b64), b64_len);
	AN(bio);
	BIO_push(b64bio, bio);

	*out_len = BIO_read(b64bio, buf, b64_len);
	assert(*out_len >= 0);

	BIO_free_all(b64bio);
	return (buf);
}

/*
 * Password callback for PEM reading.
 * Returns 0 to indicate no password is available, which causes encrypted
 * PEM files to fail loading rather than prompting on stdin.
 */
static int
pass_cb(char *buf, int size, int rwflag, void *priv)
{
	(void)buf;
	(void)size;
	(void)rwflag;
	(void)priv;
	return (0);
}

/*
 * Set DH parameters on SSL_CTX.
 * If dh/dhlen is provided, use that; otherwise try to read from src BIO.
 * Returns 0 on success, -1 on error.
 *
 * Note: The DH API is deprecated in OpenSSL 3.0 but still functional.
 * We suppress deprecation warnings for this function.
 */
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
static int
vtls_set_dh(struct cli *cli, struct vtls_ctx *vc, BIO *src,
    const char *dh, int dhlen)
{
	char errbuf[256];
	BIO *dh_src = NULL;
	DH *dhparam;
	unsigned long e;
	int err;

	CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);

	if (dhlen > 0) {
		AN(dh);
		dh_src = BIO_new_mem_buf(TRUST_ME(dh), dhlen);
		if (dh_src == NULL) {
			VCLI_Out(cli, "Error in BIO_new_mem_buf for DH\n");
			return (-1);
		}
	}

	if (dh_src != NULL) {
		dhparam = PEM_read_bio_DHparams(dh_src, NULL, pass_cb, NULL);
		BIO_free(dh_src);
		if (dhparam == NULL) {
			VCLI_Out(cli, "Error: dhparams: "
			    "No DH parameters found\n");
			while ((e = ERR_get_error())) {
				ERR_error_string_n(e, errbuf, sizeof errbuf);
				VCLI_Out(cli, "%s\n", errbuf);
			}
			return (-1);
		}
	} else {
		/* Try to read DH params from the certificate PEM */
		dhparam = PEM_read_bio_DHparams(src, NULL, pass_cb, NULL);
	}

	if (dhparam == NULL)
		return (0);  /* No DH params is not an error */

	err = SSL_CTX_set_tmp_dh(vc->ctx, dhparam);
	DH_free(dhparam);

	if (err != 1) {
		VCLI_Out(cli, "Failed to set DHparam\n");
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "%s\n", errbuf);
		}
		return (-1);
	}

	return (0);
}
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif

/*
 * Create SSL_CTX from PEM data in memory.
 * If key/key_len is provided, use that for the private key.
 * Otherwise try to find the private key in the cert PEM.
 * If px509 is not NULL, the X509 certificate is returned (caller must free).
 */
static struct vtls_ctx *
vtls_ctx_new_from_pem(struct cli *cli, const char *name_id,
    const char *pem, int pem_len, const char *key, int key_len,
    const char *dh, int dh_len,
    int protos, int prefer_server_ciphers,
    const char *ciphers, const char *ciphersuites, X509 **px509)
{
	struct vtls_ctx *vc;
	BIO *src;
	X509 *x509, *t_ca;
	EVP_PKEY *pkey;
	unsigned long e;
	char errbuf[256];

	AN(pem);
	AN(pem_len);

	if (px509 != NULL)
		*px509 = NULL;

	ALLOC_OBJ(vc, VTLS_CTX_MAGIC);
	AN(vc);
	REPLACE(vc->name_id, name_id);
	vc->protos = protos;

	vc->ctx = SSL_CTX_new(TLS_server_method());
	if (vc->ctx == NULL) {
		VCLI_Out(cli, "Failed to create SSL_CTX\n");
		vtls_ctx_free(vc);
		return (NULL);
	}

	/* Set session id context */
	AN(SSL_CTX_set_session_id_context(vc->ctx,
	    (const unsigned char *)"varnishd", strlen("varnishd")));

	/* Set options */
	if (prefer_server_ciphers)
		(void)SSL_CTX_set_options(vc->ctx,
		    SSL_OP_CIPHER_SERVER_PREFERENCE);
	(void)SSL_CTX_set_options(vc->ctx, SSL_OP_NO_RENEGOTIATION);

	/* Enable ECDH */
	AN(SSL_CTX_set_ecdh_auto(vc->ctx, 1));

	/* Set ciphers if specified */
	if (ciphers != NULL && *ciphers != '\0') {
		if (SSL_CTX_set_cipher_list(vc->ctx, ciphers) != 1) {
			VCLI_Out(cli, "Invalid cipher list: %s\n", ciphers);
			vtls_ctx_free(vc);
			return (NULL);
		}
	}

	/* Set ciphersuites (TLSv1.3) if specified */
	if (ciphersuites != NULL && *ciphersuites != '\0') {
		if (SSL_CTX_set_ciphersuites(vc->ctx, ciphersuites) != 1) {
			VCLI_Out(cli, "Invalid ciphersuites: %s\n",
			    ciphersuites);
			vtls_ctx_free(vc);
			return (NULL);
		}
	}

	/* Load certificate from PEM data */
	src = BIO_new_mem_buf(TRUST_ME(pem), pem_len);
	if (src == NULL) {
		VCLI_Out(cli, "Failed to create BIO\n");
		vtls_ctx_free(vc);
		return (NULL);
	}

	x509 = PEM_read_bio_X509_AUX(src, NULL, pass_cb, NULL);
	if (x509 == NULL) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Error loading certificate: %s\n",
			    errbuf);
		}
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	if (SSL_CTX_use_certificate(vc->ctx, x509) != 1) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "SSL_CTX_use_certificate: %s\n", errbuf);
		}
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	/* Load certificate chain */
	SSL_CTX_clear_chain_certs(vc->ctx);
	while (1) {
		t_ca = PEM_read_bio_X509_AUX(src, NULL, pass_cb, NULL);
		if (t_ca == NULL) {
			e = ERR_peek_last_error();
			if (ERR_GET_LIB(e) == ERR_LIB_PEM &&
			    ERR_GET_REASON(e) == PEM_R_NO_START_LINE) {
				ERR_clear_error();
				break;
			}
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Error loading chain cert: %s\n", errbuf);
			X509_free(x509);
			BIO_free(src);
			vtls_ctx_free(vc);
			return (NULL);
		}

		if (SSL_CTX_add_extra_chain_cert(vc->ctx, t_ca) == 0) {
			ERR_error_string_n(ERR_get_error(), errbuf,
			    sizeof errbuf);
			VCLI_Out(cli, "Error adding chain cert: %s\n", errbuf);
			X509_free(t_ca);
			X509_free(x509);
			BIO_free(src);
			vtls_ctx_free(vc);
			return (NULL);
		}
	}

	/* Load private key - from separate data if provided, else from cert PEM */
	if (key != NULL && key_len > 0) {
		BIO *key_bio = BIO_new_mem_buf(TRUST_ME(key), key_len);
		if (key_bio == NULL) {
			VCLI_Out(cli, "Error creating key BIO\n");
			X509_free(x509);
			BIO_free(src);
			vtls_ctx_free(vc);
			return (NULL);
		}
		pkey = PEM_read_bio_PrivateKey(key_bio, NULL, pass_cb, NULL);
		BIO_free(key_bio);
	} else {
		BIO_reset(src);
		pkey = PEM_read_bio_PrivateKey(src, NULL, pass_cb, NULL);
	}
	if (pkey == NULL) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Error loading private key: %s\n",
			    errbuf);
		}
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	if (SSL_CTX_use_PrivateKey(vc->ctx, pkey) != 1) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "SSL_CTX_use_PrivateKey: %s\n", errbuf);
		}
		EVP_PKEY_free(pkey);
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	EVP_PKEY_free(pkey);

	/* Verify key matches certificate */
	if (SSL_CTX_check_private_key(vc->ctx) != 1) {
		while ((e = ERR_get_error())) {
			ERR_error_string_n(e, errbuf, sizeof errbuf);
			VCLI_Out(cli, "Private key mismatch: %s\n", errbuf);
		}
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}

	/* Set DH parameters */
	BIO_reset(src);
	if (vtls_set_dh(cli, vc, src, dh, dh_len) != 0) {
		X509_free(x509);
		BIO_free(src);
		vtls_ctx_free(vc);
		return (NULL);
	}
	BIO_free(src);

	/* Set up callbacks */
	if (!SSL_CTX_set_tlsext_servername_callback(vc->ctx, vtls_sni_cb)) {
		VCLI_Out(cli, "Failed to set SNI callback\n");
		X509_free(x509);
		vtls_ctx_free(vc);
		return (NULL);
	}
	SSL_CTX_set_client_hello_cb(vc->ctx, vtls_clienthello_cb, NULL);
	SSL_CTX_set_alpn_select_cb(vc->ctx, vtls_alpn_select, NULL);

	/* Return X509 to caller if requested, otherwise free it */
	if (px509 != NULL)
		*px509 = x509;
	else
		X509_free(x509);

	return (vc);
}

/*
 * CLI: vtls.cld_cert_load
 * Load certificate from manager (base64-encoded PEM data)
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_load(struct cli *cli, const char *const *av, void *priv)
{
	struct vtls *vtls = NULL;
	struct listen_sock *ls;
	struct vtls_ctx *vc;
	const char *id, *fe, *ciphers, *ciphersuites;
	const char *cert_b64, *privkey_b64, *dh_b64;
	int protos, prefer_server_ciphers, is_default;
	char *cert, *privkey, *dh;
	int cert_len, privkey_len, dh_len;
	X509 *x509 = NULL;

	(void)priv;

	/* Parse arguments:
	 * av[2] = id
	 * av[3] = frontend (empty string for global)
	 * av[4] = dh_b64 (base64-encoded DH params, or empty)
	 * av[5] = protos
	 * av[6] = prefer_server_ciphers
	 * av[7] = ciphers
	 * av[8] = ciphersuites
	 * av[9] = is_default
	 * av[10] = cert_b64 (base64-encoded certificate)
	 * av[11] = privkey_b64 (base64-encoded private key, or empty)
	 */
	AN(av[2]); AN(av[3]); AN(av[4]); AN(av[5]); AN(av[6]);
	AN(av[7]); AN(av[8]); AN(av[9]); AN(av[10]); AN(av[11]);

	id = av[2];
	fe = av[3];
	dh_b64 = av[4];
	protos = atoi(av[5]);
	prefer_server_ciphers = atoi(av[6]);
	ciphers = av[7];
	ciphersuites = av[8];
	is_default = atoi(av[9]);
	cert_b64 = av[10];
	privkey_b64 = av[11];

	/* Find target vtls struct */
	if (*fe != '\0') {
		VTAILQ_FOREACH(ls, &heritage.socks, list) {
			CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
			if (ls->tls == NULL)
				continue;
			if (strcmp(ls->name, fe) == 0) {
				vtls = ls->tls;
				break;
			}
		}
		if (vtls == NULL) {
			VCLI_Out(cli, "Frontend '%s' not found\n", fe);
			VCLI_SetResult(cli, CLIS_CANT);
			return;
		}
	} else {
		vtls = heritage.tls;
	}

	CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);

	/* Initialize scratch SNI map if not already done */
	if (vtls->sni_scratch == NULL)
		vtls->sni_scratch = vtls_sni_map_new();

	/* Decode DH data if provided */
	dh = NULL;
	dh_len = 0;
	if (*dh_b64 != '\0') {
		dh = vtls_cli_base64_decode(dh_b64, &dh_len);
		if (dh == NULL) {
			VCLI_Out(cli, "Failed to decode DH data\n");
			VCLI_SetResult(cli, CLIS_CANT);
			return;
		}
	}

	/* Decode certificate data */
	cert = vtls_cli_base64_decode(cert_b64, &cert_len);
	if (cert == NULL || cert_len == 0) {
		VCLI_Out(cli, "Failed to decode certificate data\n");
		VCLI_SetResult(cli, CLIS_CANT);
		free(cert);
		free(dh);
		return;
	}

	/* Decode private key data if provided */
	privkey = NULL;
	privkey_len = 0;
	if (*privkey_b64 != '\0') {
		privkey = vtls_cli_base64_decode(privkey_b64, &privkey_len);
		if (privkey == NULL) {
			VCLI_Out(cli, "Failed to decode private key data\n");
			VCLI_SetResult(cli, CLIS_CANT);
			free(cert);
			free(dh);
			return;
		}
	}

	/* Create SSL_CTX and get X509 for hostname extraction */
	vc = vtls_ctx_new_from_pem(cli, id, cert, cert_len, privkey, privkey_len,
	    dh, dh_len, protos, prefer_server_ciphers, ciphers, ciphersuites,
	    &x509);

	/* Clear sensitive data from memory */
	ZERO_OBJ(cert, cert_len);
	free(cert);
	if (privkey != NULL) {
		ZERO_OBJ(privkey, privkey_len);
		free(privkey);
	}
	if (dh != NULL) {
		ZERO_OBJ(dh, dh_len);
		free(dh);
	}

	if (vc == NULL) {
		X509_free(x509);
		VCLI_SetResult(cli, CLIS_CANT);
		return;
	}

	/* Extract hostnames from certificate and add to SNI map */
	if (vtls_load_x509_names(cli, vtls, vc, x509) != 0) {
		X509_free(x509);
		vtls_sni_map_remove_ctx(vtls->sni_scratch, vc);
		vtls_ctx_free(vc);
		VCLI_SetResult(cli, CLIS_CANT);
		return;
	}
	X509_free(x509);

	/* Add to ctxs list for tracking */
	VTAILQ_INSERT_TAIL(&vtls->ctxs, vc, list);

	/* If this is the default certificate, mark it for use */
	if (is_default) {
		if (vtls->d_ctx_scratch != NULL)
			vtls->d_ctx_scratch->discarded = 1;
		vtls->d_ctx_scratch = vc;
	}

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * Commit staged changes for a single vtls struct.
 * Discarded contexts are moved to the cleanup task for deferred freeing.
 */
static void
vtls_commit_one(struct vtls *vtls, struct vtls_cleanup_task *c_task)
{
	struct vtls_sni_key *k, *k_tmp;
	struct vtls_sni_key *dup, *dup_tmp;
	struct vtls_ctx *vc, *vc_tmp;

	CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);
	CHECK_OBJ_NOTNULL(c_task, VTLS_CLEANUP_MAGIC);

	/*
	 * Create sni_scratch if we have discarded contexts.
	 * This ensures we rebuild the SNI map without discarded entries.
	 */
	if (vtls->sni_scratch == NULL) {
		VTAILQ_FOREACH(vc, &vtls->ctxs, list) {
			if (vc->discarded) {
				vtls->sni_scratch = vtls_sni_map_new();
				break;
			}
		}
	}

	/* If we have staged SNI entries, build the new combined map */
	if (vtls->sni_scratch != NULL) {
		CHECK_OBJ_NOTNULL(vtls->sni_scratch, VTLS_SNI_MAP_MAGIC);

		/* Copy non-discarded entries from current SNI map to scratch */
		if (vtls->sni != NULL) {
			VRBT_FOREACH_SAFE(k, vtls_sni_rbtree, &vtls->sni->root,
			    k_tmp) {
				CHECK_OBJ_NOTNULL(k, VTLS_SNI_KEY_MAGIC);
				if (k->ctx != NULL && !k->ctx->discarded)
					vtls_sni_map_add_copy(vtls->sni_scratch,
					    k);
				VTAILQ_FOREACH_SAFE(dup, &k->dups, dups_list,
				    dup_tmp) {
					if (dup->ctx != NULL &&
					    !dup->ctx->discarded)
						vtls_sni_map_add_copy(
						    vtls->sni_scratch, dup);
				}
			}
		}

		/*
		 * Update default context. This must happen inside the
		 * sni_scratch block so we can pick from sni_scratch if needed.
		 */
		if (vtls->d_ctx_scratch != NULL)
			vtls->d_ctx = vtls->d_ctx_scratch;
		vtls->d_ctx_scratch = NULL;

		/*
		 * If default is null or discarded, pick from sni_scratch.
		 * sni_scratch only contains non-discarded entries.
		 */
		if (vtls->d_ctx == NULL || vtls->d_ctx->discarded) {
			if (!VRBT_EMPTY(&vtls->sni_scratch->root))
				vtls->d_ctx =
				    VRBT_ROOT(&vtls->sni_scratch->root)->ctx;
			else
				vtls->d_ctx = NULL;
		}

		/* Queue old SNI map for deferred cleanup */
		if (vtls->sni != NULL)
			VTAILQ_INSERT_TAIL(&c_task->sni_maps, vtls->sni, list);

		vtls->sni = vtls->sni_scratch;
		vtls->sni_scratch = NULL;
	}

	/* Move discarded contexts to cleanup task for deferred freeing */
	VTAILQ_FOREACH_SAFE(vc, &vtls->ctxs, list, vc_tmp) {
		if (vc->discarded) {
			VTAILQ_REMOVE(&vtls->ctxs, vc, list);
			VTAILQ_INSERT_TAIL(c_task->ctxs, vc, list);
		}
	}
}

/*
 * Cooling period in seconds before discarded SSL_CTX objects are freed.
 * This gives in-flight TLS handshakes time to complete.
 */
#define VTLS_COOLING_PERIOD	6.0

/*
 * Process pending cleanup tasks.
 * Called periodically from the CLI thread.
 */
void
VTLS_Poll(void)
{
	struct vtls_cleanup_task *t, *t_tmp;
	struct vtls_sni_map *m, *m_tmp;
	struct vtls_ctx *c, *c_tmp;
	unsigned n_ctx = 0, n_maps = 0;
	unsigned limit;
	vtim_mono now;

	ASSERT_CLI();
	now = VTIM_mono();
	limit = cache_param->tls_cleanup_batch;

	VTAILQ_FOREACH_SAFE(t, &cleanup_tasks, list, t_tmp) {
		CHECK_OBJ_NOTNULL(t, VTLS_CLEANUP_MAGIC);

		/* Skip tasks still in cooling period */
		if (t->cooled > now)
			break;

		/* Free SNI maps */
		VTAILQ_FOREACH_SAFE(m, &t->sni_maps, list, m_tmp) {
			CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
			VTAILQ_REMOVE(&t->sni_maps, m, list);
			vtls_sni_map_free(&m);
			n_maps++;
		}

		/* Free SSL_CTX objects, respecting batch limit */
		if (t->ctxs != NULL) {
			VTAILQ_FOREACH_SAFE(c, t->ctxs, list, c_tmp) {
				CHECK_OBJ_NOTNULL(c, VTLS_CTX_MAGIC);
				VTAILQ_REMOVE(t->ctxs, c, list);
				vtls_ctx_free(c);
				n_ctx++;
				if (n_ctx >= limit)
					goto done;
			}
			if (VTAILQ_EMPTY(t->ctxs)) {
				free(t->ctxs);
				t->ctxs = NULL;
			}
		}

		/* Remove completed task */
		if (t->ctxs == NULL && VTAILQ_EMPTY(&t->sni_maps)) {
			VTAILQ_REMOVE(&cleanup_tasks, t, list);
			FREE_OBJ(t);
		}
	}

done:
	if (n_maps || n_ctx)
		VSL(SLT_CLI, NO_VXID, "VTLS cleanup: %u maps, %u certs%s",
		    n_maps, n_ctx,
		    n_ctx >= limit ? " (batch limit)" : "");
}

/*
 * CLI: vtls.cld_cert_commit
 * Commit staged certificates
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_commit(struct cli *cli, const char *const *av, void *priv)
{
	struct listen_sock *ls;
	struct vtls_cleanup_task *c_task;

	(void)av;
	(void)priv;

	/* Create cleanup task for deferred freeing */
	ALLOC_OBJ(c_task, VTLS_CLEANUP_MAGIC);
	AN(c_task);
	c_task->cooled = VTIM_mono() + VTLS_COOLING_PERIOD;
	VTAILQ_INIT(&c_task->sni_maps);
	c_task->ctxs = malloc(sizeof(*c_task->ctxs));
	AN(c_task->ctxs);
	VTAILQ_INIT(c_task->ctxs);

	/* Commit global certificates */
	CHECK_OBJ_NOTNULL(heritage.tls, VTLS_MAGIC);
	vtls_commit_one(heritage.tls, c_task);

	/* Commit per-frontend certificates */
	VTAILQ_FOREACH(ls, &heritage.socks, list) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		if (ls->tls != NULL)
			vtls_commit_one(ls->tls, c_task);
	}

	/* Queue cleanup task */
	VTAILQ_INSERT_TAIL(&cleanup_tasks, c_task, list);

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * Find a certificate context by ID in a vtls struct
 */
static struct vtls_ctx *
vtls_find_ctx_by_id(struct vtls *vtls, const char *id)
{
	struct vtls_ctx *vc;

	CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);
	AN(id);

	VTAILQ_FOREACH(vc, &vtls->ctxs, list) {
		CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);
		if (vc->name_id != NULL && strcmp(vc->name_id, id) == 0)
			return (vc);
	}
	return (NULL);
}

/*
 * CLI: vtls.cld_cert_discard
 * Mark a certificate for discard (by ID)
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_discard(struct cli *cli, const char *const *av, void *priv)
{
	struct vtls_ctx *vc = NULL;
	struct listen_sock *ls;
	const char *id;

	(void)priv;

	AN(av[2]);
	id = av[2];

	/* Search in global vtls */
	CHECK_OBJ_NOTNULL(heritage.tls, VTLS_MAGIC);
	vc = vtls_find_ctx_by_id(heritage.tls, id);

	/* Search in per-frontend vtls */
	if (vc == NULL) {
		VTAILQ_FOREACH(ls, &heritage.socks, list) {
			CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
			if (ls->tls == NULL)
				continue;
			vc = vtls_find_ctx_by_id(ls->tls, id);
			if (vc != NULL)
				break;
		}
	}

	if (vc == NULL) {
		VCLI_Out(cli, "Certificate '%s' not found\n", id);
		VCLI_SetResult(cli, CLIS_CANT);
		return;
	}

	/* Mark for discard - actual removal happens at commit */
	vc->discarded = 1;
	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * Rollback staged changes for a single vtls struct
 */
static void
vtls_rollback_one(struct vtls *vtls)
{
	struct vtls_ctx *vc, *vc_tmp;
	struct vtls_sni_key *k, *k_tmp;

	CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);

	/* Clear the scratch SNI map */
	if (vtls->sni_scratch != NULL) {
		/* Remove ctxs that are only in scratch (not in active sni) */
		VRBT_FOREACH_SAFE(k, vtls_sni_rbtree, &vtls->sni_scratch->root,
		    k_tmp) {
			CHECK_OBJ_NOTNULL(k, VTLS_SNI_KEY_MAGIC);
			if (k->ctx != NULL &&
			    !vtls_sni_exists(vtls->sni, k->id)) {
				/* This ctx was only in scratch, remove it */
				VTAILQ_FOREACH_SAFE(vc, &vtls->ctxs, list,
				    vc_tmp) {
					if (vc == k->ctx) {
						VTAILQ_REMOVE(&vtls->ctxs, vc,
						    list);
						vtls_ctx_free(vc);
						break;
					}
				}
			}
		}
		vtls_sni_map_free(&vtls->sni_scratch);
	}

	/* Clear d_ctx_scratch */
	vtls->d_ctx_scratch = NULL;

	/* Unmark any discarded certificates */
	VTAILQ_FOREACH(vc, &vtls->ctxs, list) {
		CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);
		vc->discarded = 0;
	}
}

/*
 * CLI: vtls.cld_cert_rollback
 * Rollback uncommitted certificate changes
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_rollback(struct cli *cli, const char *const *av, void *priv)
{
	struct listen_sock *ls;

	(void)av;
	(void)priv;

	/* Rollback global */
	CHECK_OBJ_NOTNULL(heritage.tls, VTLS_MAGIC);
	vtls_rollback_one(heritage.tls);

	/* Rollback per-frontend */
	VTAILQ_FOREACH(ls, &heritage.socks, list) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		if (ls->tls != NULL)
			vtls_rollback_one(ls->tls);
	}

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * CLI: vtls.cld_cert_discard_all
 * Mark all certificates as discarded (used by reload)
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_discard_all(struct cli *cli, const char *const *av, void *priv)
{
	struct vtls_ctx *vc;
	struct listen_sock *ls;

	ASSERT_CLI();
	(void)av;
	(void)priv;

	/* Mark all ctxs in heritage.tls as discarded */
	CHECK_OBJ_NOTNULL(heritage.tls, VTLS_MAGIC);
	VTAILQ_FOREACH(vc, &heritage.tls->ctxs, list) {
		CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);
		if (!vc->discarded)
			vc->discarded = 1;
	}

	/* Mark all ctxs in per-frontend tls as discarded */
	VTAILQ_FOREACH(ls, &heritage.socks, list) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		if (ls->tls == NULL)
			continue;
		VTAILQ_FOREACH(vc, &ls->tls->ctxs, list) {
			CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);
			if (!vc->discarded)
				vc->discarded = 1;
		}
	}

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * Check if a context is referenced in a SNI map
 */
static int
vtls_ctx_in_sni_map(struct vtls_ctx *vc, struct vtls_sni_map *m)
{
	struct vtls_sni_key *k;
	struct vtls_sni_key *dup;

	if (m == NULL)
		return (0);

	CHECK_OBJ_NOTNULL(m, VTLS_SNI_MAP_MAGIC);
	CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);

	VRBT_FOREACH(k, vtls_sni_rbtree, &m->root) {
		CHECK_OBJ_NOTNULL(k, VTLS_SNI_KEY_MAGIC);
		if (k->ctx == vc)
			return (1);
		VTAILQ_FOREACH(dup, &k->dups, dups_list) {
			CHECK_OBJ_NOTNULL(dup, VTLS_SNI_KEY_MAGIC);
			if (dup->ctx == vc)
				return (1);
		}
	}
	return (0);
}

/*
 * List certificates from a single vtls struct
 */
static int
vtls_list_certs(struct cli *cli, struct vtls *vtls, const char *fe_name,
    int json, int only_staged, int *first)
{
	struct vtls_ctx *vc;
	const char *status;
	int count = 0;
	int in_sni, in_scratch;

	CHECK_OBJ_NOTNULL(vtls, VTLS_MAGIC);

	VTAILQ_FOREACH(vc, &vtls->ctxs, list) {
		CHECK_OBJ_NOTNULL(vc, VTLS_CTX_MAGIC);

		/* Determine cert location */
		in_sni = vtls_ctx_in_sni_map(vc, vtls->sni);
		in_scratch = vtls_ctx_in_sni_map(vc, vtls->sni_scratch);

		/* Determine status */
		if (vc->discarded)
			status = "discard";
		else if (in_scratch && !in_sni)
			status = "staged";
		else if (vtls->d_ctx == vc)
			status = "active";
		else
			status = "active";

		/* Filter by staged if requested */
		if (only_staged) {
			/* Show staged and discarded only */
			if (!vc->discarded && !in_scratch)
				continue;
			/* Don't show active certs in staged-only mode */
			if (in_sni && !vc->discarded)
				continue;
		}

		if (json) {
			if (!*first)
				VCLI_Out(cli, ",\n");
			VCLI_Out(cli, "  {\"frontend\": \"%s\", "
			    "\"id\": \"%s\", \"status\": \"%s\", "
			    "\"subject\": \"%s\"}",
			    fe_name,
			    vc->name_id ? vc->name_id : "",
			    status,
			    vc->subject ? vc->subject : "");
			*first = 0;
		} else {
			VCLI_Out(cli, "%s\t%s\t%s\t%s\n",
			    fe_name,
			    vc->name_id ? vc->name_id : "",
			    status,
			    vc->subject ? vc->subject : "");
		}
		count++;
	}

	return (count);
}

/*
 * CLI: vtls.cld_cert_list
 * List loaded certificates
 */
static void v_matchproto_(cli_func_t)
vtls_cli_cert_list(struct cli *cli, const char *const *av, void *priv)
{
	struct listen_sock *ls;
	int json, only_staged;
	int first = 1;

	(void)priv;

	AN(av[2]);
	AN(av[3]);
	json = atoi(av[2]);
	only_staged = atoi(av[3]);

	if (json)
		VCLI_Out(cli, "[\n");

	/* List global certificates */
	CHECK_OBJ_NOTNULL(heritage.tls, VTLS_MAGIC);
	(void)vtls_list_certs(cli, heritage.tls, "default",
	    json, only_staged, &first);

	/* List per-frontend certificates */
	VTAILQ_FOREACH(ls, &heritage.socks, list) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		if (ls->tls != NULL)
			(void)vtls_list_certs(cli, ls->tls, ls->name,
			    json, only_staged, &first);
	}

	if (json)
		VCLI_Out(cli, "\n]\n");

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * CLI command table
 */
static struct cli_proto vtls_cli_cmds[] = {
	{ CLICMD_VTLS_CLD_CERT_LOAD, vtls_cli_cert_load, vtls_cli_cert_load },
	{ CLICMD_VTLS_CLD_CERT_COMMIT, vtls_cli_cert_commit,
	    vtls_cli_cert_commit },
	{ CLICMD_VTLS_CLD_CERT_DISCARD, vtls_cli_cert_discard,
	    vtls_cli_cert_discard },
	{ CLICMD_VTLS_CLD_CERT_ROLLBACK, vtls_cli_cert_rollback,
	    vtls_cli_cert_rollback },
	{ CLICMD_VTLS_CLD_CERT_DISCARD_ALL, vtls_cli_cert_discard_all,
	    vtls_cli_cert_discard_all },
	{ CLICMD_VTLS_CLD_CERT_LIST, vtls_cli_cert_list, vtls_cli_cert_list },
	{ NULL }
};

/* Initialize certificate subsystem */
void
VTLS_tls_cert_init(void)
{
	/* Register CLI commands */
	CLI_AddFuncs(vtls_cli_cmds);
}

