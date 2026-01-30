/*-
 * Copyright (c) 2019-2026 Varnish Software AS
 * All rights reserved.
 *
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
 * Manager process TLS configuration
 */

#include "config.h"

/*
 * OpenSSL headers include pthread.h, and mgt.h has a check for
 * pthread being included. Define MGT_ALLOW_PTHREAD first.
 */
#define MGT_ALLOW_PTHREAD

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>

#include "mgt/mgt.h"
#include "common/heritage.h"
#include "acceptor/mgt_acceptor.h"
#include "acceptor/cache_acceptor.h"

#include "vav.h"
#include "vcli_serve.h"
#include "vfil.h"
#include "mgt/mgt_tls_conf.h"
#include "vqueue.h"
#include "vsb.h"
#include "vtls_cfg/vtls_cfg_parser.h"

extern FILE *yyin;
extern int yyparse(struct vtls_cfg *cfg);

/*
 * Manager-side certificate state
 */
enum vtls_mgt_cert_state {
	VTLS_CERT_STATE_COMMITTED = 1,
	VTLS_CERT_STATE_DISCARDED,
	VTLS_CERT_STATE_MGMT,
	VTLS_CERT_STATE_STAGED,
};

struct vtls_mgt_cert {
	unsigned			magic;
#define VTLS_MGT_CERT_MAGIC		0xb4d533d5
	char				*id;
	char				*fe;
	char				*fn_cert;
	char				*fn_key;
	char				*fn_dh;
	char				*ciphers;
	char				*ciphersuites;
	int				protos;
	int				prefer_server_ciphers;
	unsigned			is_default;
	enum vtls_mgt_cert_state	state;
	VTAILQ_ENTRY(vtls_mgt_cert)	list;
};

static VTAILQ_HEAD(, vtls_mgt_cert) certs =
    VTAILQ_HEAD_INITIALIZER(certs);

/* Forward declaration */
static int mgt_tls_cert_execute_commit(unsigned int *status, char **p);

static int
mgt_tls_cert_id_unique(const char *id)
{
	struct vtls_mgt_cert *c;

	if (id == NULL)
		return (1);

	VTAILQ_FOREACH(c, &certs, list) {
		CHECK_OBJ_NOTNULL(c, VTLS_MGT_CERT_MAGIC);
		AN(c->id);
		if (strcmp(id, c->id) == 0 &&
		    c->state != VTLS_CERT_STATE_DISCARDED)
			return (0);
	}

	return (1);
}

static char *
mgt_cert_generate_id(void)
{
	char buf[32];
	static unsigned seq = 0;
	char *ret = NULL;

	bprintf(buf, "cert%u", seq++);
	REPLACE(ret, buf);
	return (ret);
}

static int
vtls_check_enabled(void)
{
	struct listen_sock *ls;

	VTAILQ_FOREACH(ls, &heritage.socks, list) {
		CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
		if (ls->tls != NULL)
			return (1);
	}

	return (0);
}

#define VTLS_CLI_CHECK()						\
	do {								\
		if (vtls_check_enabled() == 0) {			\
			VCLI_Out(cli, "TLS has not been configured");	\
			VCLI_SetResult(cli, CLIS_CANT);			\
			return;						\
		}							\
	} while (0)

/* Test if the supplied address is a numeric IPv6 address */
static int
is_ipv6(const char *host)
{
	struct addrinfo hints;
	struct addrinfo *res;
	int ret;
	AN(host);

	memset(&hints, 0, sizeof hints);
	hints.ai_family		= AF_UNSPEC;
	hints.ai_socktype	= SOCK_STREAM;
	hints.ai_flags		= AI_NUMERICHOST;

	ret = getaddrinfo(host, NULL, &hints, &res);
	if (ret != 0)
		return (0);

	ret = res->ai_family == AF_INET6;
	freeaddrinfo(res);
	return (ret);
}

static void
frontend_fmt(struct vsb *vsb, const char *host, const char *port)
{
	size_t len;

	if (host)
		len = strlen(host);
	else
		len = 0;

	/* Varnish uses empty string for INADDR_ANY */
	if (len == 0 || (len == 1 && *host == '*')) {
		VSB_printf(vsb, ":%s", port);
		return;
	}

	if (*host == '/')
		VSB_printf(vsb, "%s", host);
	else if (is_ipv6(host))
		VSB_printf(vsb, "[%s]:%s", host, port);
	else
		VSB_printf(vsb, "%s:%s", host, port);
}

static void
vtls_cfg_opts_init(struct vtls_cfg_opts *opts)
{
	static struct vtls_cfg_opts opts_initial = {
		.ciphers =			NULL,
		.ciphersuites =			NULL,
		.protos =			0,
		.prefer_server_ciphers =	0,
		.sni_nomatch_abort =		0,
		.ecdh_curve = 			NULL,
	};

	AN(opts);
	memcpy(opts, &opts_initial, sizeof(opts_initial));
	REPLACE(opts->ecdh_curve, "auto");
}

static void
vtls_cfg_opts_free(struct vtls_cfg_opts *o)
{
	AN(o);
	free(o->ciphers);
	free(o->ciphersuites);
	free(o->ecdh_curve);
}

static void
vtls_cert_cfg_free(struct vtls_cert_cfg **cert)
{
	struct vtls_cert_cfg *pc;

	AN(cert);
	TAKE_OBJ_NOTNULL(pc, cert, VTLS_CERT_CFG_MAGIC);
	free(pc->cert);
	free(pc->priv);
	free(pc->dhparam);
	free(pc->ciphers);
	free(pc->ciphersuites);
	free(pc->id);
	FREE_OBJ(pc);
}

static void
vtls_frontend_cfg_free(struct vtls_frontend_cfg **f)
{
	struct vtls_cert_cfg *cert, *cert2;
	struct vtls_frontend_cfg *fp;

	AN(f);
	TAKE_OBJ_NOTNULL(fp, f, VTLS_FRONTEND_CFG_MAGIC);
	free(fp->host);
	free(fp->port);
	free(fp->argspec);
	free(fp->name);
	vtls_cfg_opts_free(fp->opts);

	VTAILQ_FOREACH_SAFE(cert, &fp->certs, list, cert2) {
		CHECK_OBJ_NOTNULL(cert, VTLS_CERT_CFG_MAGIC);
		VTAILQ_REMOVE(&fp->certs, cert, list);
		vtls_cert_cfg_free(&cert);
	}

	FREE_OBJ(fp);
}

static void
vtls_cfg_free(struct vtls_cfg **c)
{
	struct vtls_frontend_cfg *fc, *fc2;
	struct vtls_cert_cfg *cert, *cert2;
	struct vtls_cfg *pc;

	AN(c);
	TAKE_OBJ_NOTNULL(pc, c, VTLS_CFG_MAGIC);

	VTAILQ_FOREACH_SAFE(fc, &pc->frontends, list, fc2) {
		CHECK_OBJ_NOTNULL(fc, VTLS_FRONTEND_CFG_MAGIC);
		VTAILQ_REMOVE(&pc->frontends, fc, list);
		vtls_frontend_cfg_free(&fc);
	}

	VTAILQ_FOREACH_SAFE(cert, &pc->certs, list, cert2) {
		CHECK_OBJ_NOTNULL(cert, VTLS_CERT_CFG_MAGIC);
		VTAILQ_REMOVE(&pc->certs, cert, list);
		vtls_cert_cfg_free(&cert);
	}

	vtls_cfg_opts_free(pc->opts);
	FREE_OBJ(pc);
}

static struct vtls_mgt_cert *
vtls_mgt_insert_cert(const struct vtls_cert_cfg *c_cfg,
    const struct vtls_cfg *gcfg, const struct vtls_frontend_cfg *fcfg,
    unsigned is_default)
{
	struct vtls_mgt_cert *c;
	struct vsb *fe_vsb;
	ALLOC_OBJ(c, VTLS_MGT_CERT_MAGIC);
	AN(c);

	CHECK_OBJ_NOTNULL(gcfg, VTLS_CFG_MAGIC);
	CHECK_OBJ_ORNULL(fcfg, VTLS_FRONTEND_CFG_MAGIC);

	c->is_default = is_default;

	if (fcfg) {
		fe_vsb = VSB_new_auto();
		if (fcfg->argspec)
			VSB_printf(fe_vsb, "%s", fcfg->argspec);
		else if (fcfg->host)
			VSB_printf(fe_vsb, "%s:%s", fcfg->host, fcfg->port);
		else
			VSB_printf(fe_vsb, ":%s", fcfg->port);
		VSB_finish(fe_vsb);
		if (fcfg->name != NULL)
			c->fe = strdup(fcfg->name);
		else
			c->fe = strdup(VSB_data(fe_vsb));
		VSB_destroy(&fe_vsb);
	}

	/* Set server cipher preference to TRUE/FALSE, if set on FE or Cert
	   level override global setting */
	c->prefer_server_ciphers = gcfg->opts->prefer_server_ciphers;
	if (fcfg && fcfg->opts->prefer_server_ciphers != -1)
		c->prefer_server_ciphers = fcfg->opts->prefer_server_ciphers;

	REPLACE(c->fn_cert, c_cfg->cert);
	REPLACE(c->id, c_cfg->id);
	REPLACE(c->fn_key, c_cfg->priv);
	REPLACE(c->fn_dh, c_cfg->dhparam);

	c->state = VTLS_CERT_STATE_MGMT;

	if (c_cfg->ciphers != NULL)
		REPLACE(c->ciphers, c_cfg->ciphers);

	if (NULL == c->ciphers && fcfg && fcfg->opts->ciphers != NULL)
		REPLACE(c->ciphers, fcfg->opts->ciphers);

	if (NULL == c->ciphers && gcfg && gcfg->opts->ciphers != NULL)
		REPLACE(c->ciphers, gcfg->opts->ciphers);

	if (c_cfg->ciphersuites)
		REPLACE(c->ciphersuites, c_cfg->ciphersuites);

	if (fcfg && fcfg->opts->ciphersuites)
		REPLACE(c->ciphersuites, fcfg->opts->ciphersuites);

	if (NULL == c->ciphersuites && gcfg && gcfg->opts->ciphersuites)
		REPLACE(c->ciphersuites, gcfg->opts->ciphersuites);

	return (c);
}

static struct vtls *
vtls_init_local(const struct vtls_cfg *gcfg,
    const struct vtls_frontend_cfg *fcfg)
{
	struct vtls_cert_cfg *certcfg;
	struct vtls *v;
	struct vtls_mgt_cert *vc;

	CHECK_OBJ_NOTNULL(gcfg, VTLS_CFG_MAGIC);
	CHECK_OBJ_NOTNULL(fcfg, VTLS_FRONTEND_CFG_MAGIC);

	ALLOC_OBJ(v, VTLS_MAGIC);
	AN(v);
	VTAILQ_INIT(&v->ctxs);

	v->protos = fcfg->opts->protos;

	v->cfg->sni_nomatch_abort = fcfg->opts->sni_nomatch_abort;

	if (v->cfg->sni_nomatch_abort == -1)
		v->cfg->sni_nomatch_abort = gcfg->opts->sni_nomatch_abort;

	if (fcfg->sni_match_global == -1) {
		if (VTAILQ_EMPTY(&fcfg->certs))
			v->sni_match_global = 1;
		else
			v->sni_match_global = 0;
	} else
		v->sni_match_global = fcfg->sni_match_global;

	VTAILQ_FOREACH(certcfg, &fcfg->certs, list) {
		vc = vtls_mgt_insert_cert(certcfg, gcfg, fcfg,
			VTAILQ_NEXT(certcfg, list) == NULL);
		if (vc->id == NULL)
			vc->id = mgt_cert_generate_id();
		if (!mgt_tls_cert_id_unique(vc->id))
			ARGV_ERR("Certificate ID '%s' already exists.", vc->id);
		VTAILQ_INSERT_TAIL(&certs, vc, list);
	}

	v->d_ctx = NULL;

	return (v);
}

static struct vtls *
vtls_init_global(const struct vtls_cfg *c)
{
	struct vtls_cert_cfg *certcfg;
	struct vtls *v;
	struct vtls_mgt_cert *vc;

	CHECK_OBJ_NOTNULL(c, VTLS_CFG_MAGIC);
	ALLOC_OBJ(v, VTLS_MAGIC);
	AN(v);
	VTAILQ_INIT(&v->ctxs);

	v->protos = c->opts->protos;
	v->cfg->sni_nomatch_abort = c->opts->sni_nomatch_abort;

	VTAILQ_FOREACH(certcfg, &c->certs, list) {
		vc = vtls_mgt_insert_cert(certcfg, c, NULL,
			VTAILQ_NEXT(certcfg, list) == NULL);
		if (vc->id == NULL)
			vc->id = mgt_cert_generate_id();
		if (!mgt_tls_cert_id_unique(vc->id))
			ARGV_ERR("Certificate ID '%s' already exists.", vc->id);
		VTAILQ_INSERT_TAIL(&certs, vc, list);
	}

	v->d_ctx = NULL;

	return (v);
}

struct vtls_frontend_cfg *
VTLS_frontend_cfg_alloc(void)
{
	struct vtls_frontend_cfg *fc;

	ALLOC_OBJ(fc, VTLS_FRONTEND_CFG_MAGIC);
	AN(fc);

	vtls_cfg_opts_init(fc->opts);
	fc->opts->sni_nomatch_abort = -1;
	fc->opts->prefer_server_ciphers = -1;
	fc->sni_match_global = -1;
	VTAILQ_INIT(&fc->certs);

	return (fc);
}

static struct vsb *
mgt_cert_load_file_b64(const char *filename)
{
	BIO *bio, *b64;
	BUF_MEM *b64_result;
	ssize_t sz = 0;
	int ret;
	char *file;
	struct vsb *vsb;

	AN(filename);

	VJ_master(JAIL_MASTER_FILE);
	file = VFIL_readfile(NULL, filename, &sz);
	VJ_master(JAIL_MASTER_LOW);

	if (file == NULL)
		return (NULL);

	vsb = VSB_new_auto();
	b64 = BIO_new(BIO_f_base64());
	AN(b64);

	bio = BIO_new(BIO_s_mem());
	AN(bio);

	BIO_push(b64, bio);

	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	ret = BIO_write(b64, file, sz);
	assert(ret == sz);

	ret = BIO_flush(b64);
	assert(ret == 1);

	BIO_get_mem_ptr(b64, &b64_result);

	VSB_bcat(vsb, b64_result->data, b64_result->length);

	BIO_free_all(b64);
	ZERO_OBJ(TRUST_ME(file), sz);
	free(file);

	VSB_finish(vsb);

	return (vsb);
}

static int
mgt_cert_load_cld(unsigned *status, struct vsb *e_msg,
    struct vtls_mgt_cert *cert)
{
	char *p;
	struct vsb *cmd;
	struct vsb *crt = NULL, *privkey = NULL, *dh = NULL;

	AN(status);
	AN(e_msg);
	CHECK_OBJ(cert, VTLS_MGT_CERT_MAGIC);

	/* Load certificate file */
	crt = mgt_cert_load_file_b64(cert->fn_cert);
	if (crt == NULL) {
		VSB_printf(e_msg, "Unable to read certificate file '%s' (%s)\n",
		    cert->fn_cert, strerror(errno));
		*status = CLIS_CANT;
		goto err;
	}

	/* Load private key file if separate */
	if (cert->fn_key != NULL) {
		privkey = mgt_cert_load_file_b64(cert->fn_key);
		if (privkey == NULL) {
			VSB_printf(e_msg,
			    "Unable to read private key file '%s' (%s)\n",
			    cert->fn_key, strerror(errno));
			*status = CLIS_CANT;
			goto err;
		}
	}

	/* Load DH parameters file if specified */
	if (cert->fn_dh != NULL) {
		dh = mgt_cert_load_file_b64(cert->fn_dh);
		if (dh == NULL) {
			VSB_printf(e_msg, "Unable to read dh file '%s' (%s)\n",
			    cert->fn_dh, strerror(errno));
			*status = CLIS_CANT;
			goto err;
		}
	}

	if (VSB_len(crt) == 0) {
		VSB_printf(e_msg, "File '%s' is empty.\n", cert->fn_cert);
		*status = CLIS_PARAM;
		goto err;
	} else if (MCH_Running()) {
		cmd = VSB_new_auto();
		AN(cmd);

		AN(cert->id);
		/*
		 * CLI: vtls.cld_cert_load <id> <frontend> <protos>
		 *      <prefer_server_ciphers> <ciphers> <ciphersuites>
		 *      <is_default> <cert_b64> <privkey_b64>
		 */
		VSB_printf(cmd, "\"%s\" ", cert->id);
		VSB_printf(cmd, "\"%s\" ",
		    cert->fe != NULL ? cert->fe : "");
		VSB_printf(cmd, "\"%i\" ", cert->protos);
		VSB_printf(cmd, "\"%i\" ", cert->prefer_server_ciphers);
		VSB_printf(cmd, "\"%s\" ",
		    cert->ciphers != NULL ? cert->ciphers : "");
		VSB_printf(cmd, "\"%s\" ",
		    cert->ciphersuites != NULL ? cert->ciphersuites : "");
		VSB_printf(cmd, "\"%i\" ", cert->is_default);
		VSB_printf(cmd, "\"%s\" ", VSB_data(crt));
		VSB_printf(cmd, "\"%s\" ",
		    privkey != NULL ? VSB_data(privkey) : "");
		AZ(VSB_finish(cmd));

		if (mgt_cli_askchild(status, &p, "vtls.cld_cert_load %s\n",
		    VSB_data(cmd))) {
			VSB_printf(e_msg, "%s: %s", cert->fn_cert, p);
		}
		free(p);
		VSB_destroy(&cmd);
		if (*status != CLIS_OK)
			goto err;
	} else {
		VSB_printf(e_msg, "Child not running");
		*status = CLIS_CANT;
	}

err:
	if (crt != NULL)
		VSB_destroy(&crt);

	if (privkey != NULL)
		VSB_destroy(&privkey);

	if (dh != NULL)
		VSB_destroy(&dh);

	AZ(VSB_finish(e_msg));
	return (*status != CLIS_OK);
}

/*
 * Push certificates to the child process at startup
 * Returns 0 on success, 1 on failure
 */
int
MGT_TLS_push_server_certs(unsigned *statusp, char **pp)
{
	struct vtls_mgt_cert *c;
	struct vsb *e_msg;
	unsigned status = CLIS_OK;
	int e = 0;

	if (pp != NULL)
		*pp = NULL;
	if (statusp != NULL)
		*statusp = CLIS_OK;

	if (!vtls_check_enabled())
		return (0);

	e_msg = VSB_new_auto();
	AN(e_msg);

	VTAILQ_FOREACH(c, &certs, list) {
		CHECK_OBJ_NOTNULL(c, VTLS_MGT_CERT_MAGIC);
		/* Push certs in MGMT or COMMITTED state (for reload) */
		if (c->state != VTLS_CERT_STATE_MGMT &&
		    c->state != VTLS_CERT_STATE_COMMITTED)
			continue;

		VSB_clear(e_msg);
		if (mgt_cert_load_cld(&status, e_msg, c)) {
			/* e_msg is already finished by mgt_cert_load_cld */
			if (statusp != NULL)
				*statusp = status;
			if (pp != NULL)
				*pp = strdup(VSB_data(e_msg));
			e = 1;
			break;
		}
	}

	VSB_destroy(&e_msg);

	/* On success, commit all pushed certs */
	if (e == 0) {
		e = mgt_tls_cert_execute_commit(&status, pp);
		if (statusp != NULL)
			*statusp = status;
	}

	return (e);
}

/*
 * Parse a TLS configuration file specified by -A
 */
int
TLS_Config(const char *fn)
{
	struct vtls_cfg *cfg;
	struct vtls_frontend_cfg *fcfg;
	struct vsb *vsb;
	struct listen_sock *ls;
	int n;

	AN(fn);

	VJ_master(JAIL_MASTER_FILE);
	yyin = fopen(fn, "r");
	VJ_master(JAIL_MASTER_LOW);

	if (yyin == NULL)
		ARGV_ERR("-A: Cannot open '%s': %s\n", fn, strerror(errno));

	ALLOC_OBJ(cfg, VTLS_CFG_MAGIC);
	AN(cfg);
	vtls_cfg_opts_init(cfg->opts);
	VTAILQ_INIT(&cfg->frontends);
	VTAILQ_INIT(&cfg->certs);

	if (yyparse(cfg) != 0) {
		vtls_cfg_free(&cfg);
		AZ(fclose(yyin));
		return (-1);
	}

	AZ(fclose(yyin));

	/* Check that at least one frontend is defined */
	if (VTAILQ_EMPTY(&cfg->frontends))
		ARGV_ERR("-A: No frontend listen endpoint definitions "
		    "found in configuration file %s\n", fn);

	/* Initialize global TLS config */
	heritage.tls = vtls_init_global(cfg);

	/* Process frontends and create listen sockets */
	VTAILQ_FOREACH(fcfg, &cfg->frontends, list) {
		void *tls_local;
		const char *sockname;

		CHECK_OBJ_NOTNULL(fcfg, VTLS_FRONTEND_CFG_MAGIC);

		/* Auto-generate name for unnamed frontends */
		if (fcfg->name == NULL) {
			static unsigned tls_name_seq = 0;
			char name_buf[16];

			bprintf(name_buf, "tls%u", tls_name_seq++);
			fcfg->name = strdup(name_buf);
			AN(fcfg->name);
		}

		/* Initialize TLS configuration for this frontend */
		tls_local = vtls_init_local(cfg, fcfg);

		vsb = VSB_new_auto();
		AN(vsb);

		/* Build the -a argument string: name=host:port,TLS */
		if (fcfg->name != NULL) {
			sockname = fcfg->name;
			VSB_printf(vsb, "%s=", fcfg->name);
		} else {
			sockname = NULL;
		}

		if (fcfg->argspec != NULL) {
			VSB_printf(vsb, "%s,TLS", fcfg->argspec);
		} else {
			frontend_fmt(vsb, fcfg->host, fcfg->port);
			VSB_cat(vsb, ",TLS");
		}
		AZ(VSB_finish(vsb));

		/* Use VCA_Arg to create and bind the socket */
		VCA_Arg(VSB_data(vsb));

		/* Find the created listen_sock(s) and attach TLS config.
		 * An endpoint may resolve to multiple addresses (e.g.
		 * both IPv4 and IPv6), so attach to all matching sockets.
		 */
		n = 0;
		VTAILQ_FOREACH(ls, &heritage.socks, list) {
			CHECK_OBJ_NOTNULL(ls, LISTEN_SOCK_MAGIC);
			if (ls->tls == NULL &&
			    ls->transport == XPORT_Find("TLS") &&
			    (sockname == NULL ||
			     strcmp(ls->name, sockname) == 0)) {
				ls->tls = tls_local;
				n++;
			}
		}
		if (n == 0)
			ARGV_ERR("-A: Failed to create TLS"
			    " socket for %s\n", VSB_data(vsb));

		VSB_destroy(&vsb);
	}

	vtls_cfg_free(&cfg);
	return (0);
}

/*--------------------------------------------------------------------
 * Public CLI commands for TLS certificate management
 */

static void
mgt_tls_cert_free(struct vtls_mgt_cert *c)
{
	CHECK_OBJ_NOTNULL(c, VTLS_MGT_CERT_MAGIC);

	free(c->id);
	free(c->fe);
	free(c->fn_cert);
	free(c->fn_key);
	free(c->fn_dh);
	free(c->ciphers);
	free(c->ciphersuites);
	FREE_OBJ(c);
}

/*
 * CLI: tls.cert.load
 */
static void v_matchproto_(cli_func_t)
mgt_tls_cert_load(struct cli *cli, const char * const *av, void *priv)
{
	(void)priv;
	struct vtls_mgt_cert *cert;
	struct vsb *e_msg;
	unsigned status;

	int i = 2;

	ALLOC_OBJ(cert, VTLS_MGT_CERT_MAGIC);
	AN(cert);

	/* First positional arg may be cert-id or filename */
	if (av[i + 1] != NULL && *av[i + 1] != '-') {
		REPLACE(cert->id, av[i]);
		REPLACE(cert->fn_cert, av[i + 1]);
		i++;
	} else {
		REPLACE(cert->fn_cert, av[i]);
	}

	i++;

	if (cert->id == NULL)
		cert->id = mgt_cert_generate_id();
	if (!mgt_tls_cert_id_unique(cert->id)) {
		VCLI_Out(cli, "Id: \"%s\" already exists", cert->id);
		VCLI_SetResult(cli, CLIS_CANT);
		mgt_tls_cert_free(cert);
		return;
	}

#define MGT_TLS_PARSE_ARG(flag, val)					\
	if (strcmp(av[i], flag) == 0) {					\
		if (av[i + 1] != NULL && *av[i + 1] != '-') {		\
			i++;						\
			REPLACE(val, av[i]);				\
		} else {						\
			VCLI_Out(cli, "No value specified for: %s", av[i]); \
			VCLI_SetResult(cli, CLIS_CANT);			\
			mgt_tls_cert_free(cert);			\
			return;						\
		}							\
	} else

	for (; av[i] != NULL; i++) {
		MGT_TLS_PARSE_ARG("-f", cert->fe)
		MGT_TLS_PARSE_ARG("-c", cert->ciphers)
		MGT_TLS_PARSE_ARG("-k", cert->fn_key)
		MGT_TLS_PARSE_ARG("-s", cert->ciphersuites)

		/* The macro above turns this into an else if */
		if (strcmp(av[i], "-p") == 0) {
			char **proto_av;
			int j;

			if (av[i+1] == NULL) {
				VCLI_Out(cli, "No value specified for: %s",
				    av[i]);
				VCLI_SetResult(cli, CLIS_CANT);
				mgt_tls_cert_free(cert);
				return;
			}
			i++;
			proto_av = VAV_Parse(av[i], NULL, ARGV_COMMA);

			for (j = 1; proto_av[j] != NULL; j++) {
#define VTLS_PROTO(vtls_proto, n, ssl_proto, s)				\
				if (strcasecmp(proto_av[j], s) == 0) {	\
					cert->protos |= vtls_proto;	\
					continue;			\
				}					\
				else
#include "common/common_tls_protos.h"
#undef VTLS_PROTO
				{
					VCLI_Out(cli,
					    "Unknown protocol specifier: %s",
					    proto_av[j]);
					VCLI_SetResult(cli, CLIS_CANT);
					mgt_tls_cert_free(cert);
					VAV_Free(proto_av);
					return;
				}
			}
			VAV_Free(proto_av);
		} else if (strcmp(av[i], "-d") == 0) {
			cert->is_default = 1;
		} else if (strcmp(av[i], "-o") == 0) {
			cert->prefer_server_ciphers = 1;
		} else {
			VCLI_Out(cli, "Unknown TLS option: %s", av[i]);
			VCLI_SetResult(cli, CLIS_CANT);
			mgt_tls_cert_free(cert);
			return;
		}
	}
#undef MGT_TLS_PARSE_ARG

	e_msg = VSB_new_auto();
	AN(e_msg);

	if (mgt_cert_load_cld(&status, e_msg, cert) == 0) {
		cert->state = VTLS_CERT_STATE_STAGED;
		VTAILQ_INSERT_TAIL(&certs, cert, list);
	} else {
		VCLI_Out(cli, "%s", VSB_data(e_msg));
		mgt_tls_cert_free(cert);
	}

	VSB_destroy(&e_msg);
	VCLI_SetResult(cli, status);
}

static int
mgt_tls_cert_execute_commit(unsigned int *status, char **p)
{
	struct vtls_mgt_cert *c;
	struct vtls_mgt_cert *tc;
	int res;

	res = mgt_cli_askchild(status, p, "vtls.cld_cert_commit\n");

	/* Now free discarded certs and update states */
	VTAILQ_FOREACH_SAFE(c, &certs, list, tc) {
		CHECK_OBJ_NOTNULL(c, VTLS_MGT_CERT_MAGIC);
		if (c->state != VTLS_CERT_STATE_DISCARDED) {
			if (c->state != VTLS_CERT_STATE_MGMT)
				c->state = VTLS_CERT_STATE_COMMITTED;
			continue;
		}

		VTAILQ_REMOVE(&certs, c, list);
		mgt_tls_cert_free(c);
	}

	return (res);
}

/*
 * CLI: tls.cert.commit
 */
static void v_matchproto_(cli_func_t)
mgt_tls_cert_commit(struct cli *cli, const char * const *av, void *priv)
{
	char *p;
	unsigned status;

	(void)priv;
	(void)av;

	if (MCH_Running()) {
		mgt_tls_cert_execute_commit(&status, &p);
		VCLI_Out(cli, "%s", p);
		VCLI_SetResult(cli, status);
		free(p);
	}
}

/*
 * CLI: tls.cert.discard
 */
static void v_matchproto_(cli_func_t)
mgt_tls_cert_discard(struct cli *cli, const char * const *av, void *priv)
{
	char *p;
	unsigned status, found = 0;
	struct vtls_mgt_cert *c;
	struct vtls_mgt_cert *tc;
	(void)priv;

	if (MCH_Running()) {
		VTAILQ_FOREACH_SAFE(c, &certs, list, tc) {
			CHECK_OBJ_NOTNULL(c, VTLS_MGT_CERT_MAGIC);
			if (strcmp(c->id, av[2]) != 0)
				continue;

			found = 1;
			mgt_cli_askchild(&status, &p,
			    "vtls.cld_cert_discard %s\n", c->id);
			VCLI_Out(cli, "%s", p);
			VCLI_SetResult(cli, status);
			free(p);

			if (status == CLIS_OK)
				c->state = VTLS_CERT_STATE_DISCARDED;
		}
	}

	if (!found) {
		VCLI_Out(cli, "ID not found");
		VCLI_SetResult(cli, CLIS_CANT);
	}
}

/*
 * CLI: tls.cert.rollback
 */
static void v_matchproto_(cli_func_t)
mgt_tls_cert_rollback(struct cli *cli, const char * const *av, void *priv)
{
	char *p;
	unsigned status;
	struct vtls_mgt_cert *c;
	struct vtls_mgt_cert *tc;

	(void)priv;
	(void)av;

	if (MCH_Running()) {
		VTAILQ_FOREACH_SAFE(c, &certs, list, tc) {
			CHECK_OBJ_NOTNULL(c, VTLS_MGT_CERT_MAGIC);

			if (c->state == VTLS_CERT_STATE_DISCARDED)
				c->state = VTLS_CERT_STATE_COMMITTED;

			if (c->state != VTLS_CERT_STATE_STAGED)
				continue;

			VTAILQ_REMOVE(&certs, c, list);

			mgt_tls_cert_free(c);
		}
		mgt_cli_askchild(&status, &p, "vtls.cld_cert_rollback\n");
		VCLI_Out(cli, "%s", p);
		VCLI_SetResult(cli, status);
		free(p);
	}
}

static void v_matchproto_(cli_func_t)
mgt_tls_cert_list(struct cli *cli, const char *const *av, void *priv,
    int json, int only_staged)
{
	char *p;
	unsigned status;

	(void)av;
	(void)priv;

	if (MCH_Running()) {
		mgt_cli_askchild(&status, &p, "vtls.cld_cert_list %i %i\n",
		    json, only_staged);
		VCLI_Out(cli, "%s", p);
		VCLI_SetResult(cli, status);
		free(p);
	}
}

/*
 * CLI: tls.cert.list (text output)
 */
static void v_matchproto_(cli_func_t)
mgt_tls_cert_list_txt(struct cli *cli, const char * const *av, void *priv)
{
	int only_staged = 0;

	VTLS_CLI_CHECK();

	if (NULL != av[2] && strcmp(av[2], "-s") == 0)
		only_staged = 1;

	mgt_tls_cert_list(cli, av, priv, 0, only_staged);
}

/*
 * CLI: tls.cert.list (JSON output)
 */
static void v_matchproto_(cli_func_t)
mgt_tls_cert_list_json(struct cli *cli, const char * const *av, void *priv)
{
	int only_staged = 0;

	VTLS_CLI_CHECK();

	if (NULL != av[3] && strcmp(av[3], "-s") == 0)
		only_staged = 1;

	mgt_tls_cert_list(cli, av, priv, 1, only_staged);
}

/*
 * CLI: tls.cert.reload
 */
static void v_matchproto_(cli_func_t)
mgt_tls_cert_reload(struct cli *cli, const char * const *av, void *priv)
{
	unsigned status;
	char *p;
	(void)av;
	(void)priv;

	struct vtls_mgt_cert *c;

	VTAILQ_FOREACH(c, &certs, list) {
		CHECK_OBJ_NOTNULL(c, VTLS_MGT_CERT_MAGIC);

		if (c->state == VTLS_CERT_STATE_DISCARDED ||
		    c->state == VTLS_CERT_STATE_STAGED) {
			VCLI_Out(cli,
			    "There are staged changes, "
			    "please commit or rollback staged changes first.\n");
			VCLI_SetResult(cli, CLIS_CANT);
			return;
		}
	}

	/* Ask child to mark all current certs as discarded */
	if (mgt_cli_askchild(&status, &p, "vtls.cld_cert_discard_all\n")) {
		VCLI_Out(cli, "%s", p);
		VCLI_SetResult(cli, status);
		free(p);
		return;
	}
	free(p);

	/* Re-push all certificates */
	if (MGT_TLS_push_server_certs(&status, &p)) {
		VCLI_Out(cli, "%s", p);
		VCLI_SetResult(cli, status);
		free(p);

		mgt_cli_askchild(&status, &p, "vtls.cld_cert_rollback\n");
		free(p);
		return;
	}

	VCLI_SetResult(cli, CLIS_OK);
}

/*
 * CLI command table
 */
static struct cli_proto cli_tls_cert[] = {
	{ CLICMD_VTLS_CERT_LOAD, mgt_tls_cert_load },
	{ CLICMD_VTLS_CERT_COMMIT, mgt_tls_cert_commit },
	{ CLICMD_VTLS_CERT_DISCARD, mgt_tls_cert_discard },
	{ CLICMD_VTLS_CERT_ROLLBACK, mgt_tls_cert_rollback },
	{ CLICMD_VTLS_CERT_LIST, mgt_tls_cert_list_txt, mgt_tls_cert_list_json },
	{ CLICMD_VTLS_CERT_RELOAD, mgt_tls_cert_reload },
	{ NULL }
};

/*
 * Allocate a minimal TLS listener configuration for -a :port,https
 * Also sets up heritage.tls if not already configured, so CLI commands work.
 */
void *
TLS_Listener_Config(void)
{
	struct vtls *v;

	ALLOC_OBJ(v, VTLS_MAGIC);
	AN(v);
	VTAILQ_INIT(&v->ctxs);

	v->cfg->sni_nomatch_abort = 1;
	v->sni_match_global = 1;
	v->d_ctx = NULL;

	/* Set up heritage.tls if not already configured */
	if (heritage.tls == NULL)
		heritage.tls = v;

	return (v);
}

/*
 * Initialize TLS CLI commands (called from mgt_main.c)
 */
void
MGT_TLS_Init(void)
{
	VCLS_AddFunc(mgt_cls, cli_tls_cert);
}
