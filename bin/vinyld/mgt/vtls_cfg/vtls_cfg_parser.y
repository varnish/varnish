%{
/*-
 * Copyright (c) 2019 Varnish Software AS
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
 * TLS config file parser
 */

#include "config.h"

/*
 * OpenSSL headers include pthread.h, and mgt.h has a check for
 * pthread being included. Define MGT_ALLOW_PTHREAD first.
 */
#define MGT_ALLOW_PTHREAD

#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "mgt/mgt.h"
#include "mgt/mgt_tls_conf.h"
#include "common/heritage.h"

extern FILE *yyin;
int yyget_lineno(void);
void yyerror(struct vtls_cfg *, const char *);
int yylex(void);
extern char vtls_cfg_input_line[512];

static struct vtls_frontend_cfg *cur_fr;
static struct vtls_cert_cfg *cur_cert;

%}

%union {
	int	i;
	char	*s;
}

%token <i> INT
%token <i> UINT
%token <i> BOOL
%token <s> STRING

%token TOK_CIPHERS TOK_CIPHERSUITES TOK_PREFER_SERVER_CIPHERS
%token TOK_FRONTEND TOK_TLS_PROTOS TOK_SSLv3 TOK_TLSv1_0 TOK_TLSv1_1
%token TOK_TLSv1_2 TOK_TLSv1_3 TOK_SNI_NOMATCH_ABORT TOK_HOST TOK_PORT
%token TOK_MATCH_GLOBAL TOK_PB_CERT TOK_PEM_FILE TOK_PRIVATE_KEY
%token TOK_DHPARAM TOK_ECDH_CURVE TOK_NAME

%parse-param { struct vtls_cfg *cfg }

%%
CFG
	: CFG_RECORDS
	;

CFG_RECORDS
	: CFG_RECORD
	| CFG_RECORDS CFG_RECORD
	;

CFG_RECORD
	: FRONTEND_REC
	| PEM_FILE_REC
	| CIPHERS_REC
	| CIPHERSUITES_REC
	| TLS_PROTOS_REC
	| PREFER_SERVER_CIPHERS_REC
	| SNI_NOMATCH_ABORT_REC
	| ECDH_CURVE_REC
	;

FRONTEND_REC
	: TOK_FRONTEND '=' STRING {
		AZ(cur_fr);
		cur_fr = VTLS_frontend_cfg_alloc();
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
		REPLACE(cur_fr->argspec, $3);
		VTAILQ_INSERT_TAIL(&cfg->frontends, cur_fr, list);
		cur_fr = NULL;
	}
	| TOK_FRONTEND '=' '{' {
		AZ(cur_fr);
		cur_fr = VTLS_frontend_cfg_alloc();
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	} FRONTEND_BLK '}' {
		VTAILQ_INSERT_TAIL(&cfg->frontends, cur_fr, list);
		cur_fr = NULL;
	};

FRONTEND_BLK: FB_RECS;
FB_RECS
	: FB_REC
	| FB_RECS FB_REC
	;

FB_REC
	: FB_HOST
	| FB_PORT
	| FB_NAME
	| PEM_FILE_REC
	| FB_MATCH_GLOBAL
	| FB_SNI_NOMATCH_ABORT
	| FB_TLS_PROTOS
	| FB_CIPHERS
	| FB_CIPHERSUITES
	| FB_PREF_SRV_CIPH
	;

FB_HOST: TOK_HOST '=' STRING {
	if ($3)
		REPLACE(cur_fr->host, $3);
};

FB_PORT: TOK_PORT '=' STRING {
	if ($3)
		REPLACE(cur_fr->port, $3);
};

FB_NAME: TOK_NAME '=' STRING {
	if ($3)
		REPLACE(cur_fr->name, $3);
};

PEM_BLK: PB_RECS;

PB_RECS
	: PB_REC
	| PB_RECS PB_REC
	;

PB_REC
	: PB_CERT
	| PRIVATE_KEY
	| PB_DHPARAM
	| PB_CIPHERS
	| PB_CIPHERSUITES
	| PB_NAME
	;

PB_CERT: TOK_PB_CERT '=' STRING {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ($3)
		REPLACE(cur_cert->cert, $3);
};

PRIVATE_KEY: TOK_PRIVATE_KEY '=' STRING {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ($3)
		REPLACE(cur_cert->priv, $3);
};

PB_DHPARAM: TOK_DHPARAM '=' STRING {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ($3)
		REPLACE(cur_cert->dhparam, $3);
};

PB_CIPHERS: TOK_CIPHERS '=' STRING {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ($3) {
		REPLACE(cur_cert->ciphers, $3);
	}
};

PB_CIPHERSUITES: TOK_CIPHERSUITES '=' STRING {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ($3) {
		REPLACE(cur_cert->ciphersuites, $3);
	}
};

PB_NAME: TOK_NAME '=' STRING {
	CHECK_OBJ_NOTNULL(cur_cert, VTLS_CERT_CFG_MAGIC);
	if ($3) {
		REPLACE(cur_cert->id, $3);
	}
}

FB_MATCH_GLOBAL: TOK_MATCH_GLOBAL '=' BOOL {
	CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	cur_fr->sni_match_global = $3;
};

FB_SNI_NOMATCH_ABORT:TOK_SNI_NOMATCH_ABORT '=' BOOL {
	CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	cur_fr->opts->sni_nomatch_abort = $3;
};

FB_TLS_PROTOS: TOK_TLS_PROTOS '=' FB_TLS_PROTOS_LIST ;

FB_TLS_PROTOS_LIST: FB_TLS_PROTO | FB_TLS_PROTOS_LIST FB_TLS_PROTO;
FB_TLS_PROTO
	: TOK_SSLv3   { cur_fr->opts->protos |= SSLv3_PROTO;   }
	| TOK_TLSv1_0 { cur_fr->opts->protos |= TLSv1_0_PROTO; }
	| TOK_TLSv1_1 { cur_fr->opts->protos |= TLSv1_1_PROTO; }
	| TOK_TLSv1_2 { cur_fr->opts->protos |= TLSv1_2_PROTO; }
	| TOK_TLSv1_3 { cur_fr->opts->protos |= TLSv1_3_PROTO; };

FB_CIPHERS: TOK_CIPHERS '=' STRING {
	if ($3) {
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
		REPLACE(cur_fr->opts->ciphers, $3);
	}
};

FB_CIPHERSUITES: TOK_CIPHERSUITES '=' STRING {
	if ($3) {
		CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
		REPLACE(cur_fr->opts->ciphersuites, $3);
	}
};

FB_PREF_SRV_CIPH: TOK_PREFER_SERVER_CIPHERS '=' BOOL {
	CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
	cur_fr->opts->prefer_server_ciphers = $3;
};

TLS_PROTOS_REC: TOK_TLS_PROTOS '=' TLS_PROTOS_LIST;

TLS_PROTOS_LIST: TLS_PROTO | TLS_PROTOS_LIST TLS_PROTO;
TLS_PROTO
	: TOK_SSLv3   { cfg->opts->protos |= SSLv3_PROTO;   }
	| TOK_TLSv1_0 { cfg->opts->protos |= TLSv1_0_PROTO; }
	| TOK_TLSv1_1 { cfg->opts->protos |= TLSv1_1_PROTO; }
	| TOK_TLSv1_2 { cfg->opts->protos |= TLSv1_2_PROTO; }
	| TOK_TLSv1_3 { cfg->opts->protos |= TLSv1_3_PROTO; };

PREFER_SERVER_CIPHERS_REC: TOK_PREFER_SERVER_CIPHERS '=' BOOL {
	cfg->opts->prefer_server_ciphers = $3;
};

PEM_FILE_REC
	: TOK_PEM_FILE '=' STRING {
		if ($3) {
			ALLOC_OBJ(cur_cert, VTLS_CERT_CFG_MAGIC);
			AN(cur_cert);
			REPLACE(cur_cert->cert, $3);
			if (cur_fr != NULL) {
				CHECK_OBJ_NOTNULL(cur_fr,
				    VTLS_FRONTEND_CFG_MAGIC);
				VTAILQ_INSERT_TAIL(&cur_fr->certs,
				    cur_cert, list);
			} else
				VTAILQ_INSERT_TAIL(&cfg->certs, cur_cert, list);
			cur_cert = NULL;
		}
	}
	| TOK_PEM_FILE '=' '{' {
		/* NB: Mid-rule action */
		AZ(cur_cert);
		ALLOC_OBJ(cur_cert, VTLS_CERT_CFG_MAGIC);
	}
	PEM_BLK '}' {
		if (cur_fr != NULL) {
			CHECK_OBJ_NOTNULL(cur_fr, VTLS_FRONTEND_CFG_MAGIC);
			VTAILQ_INSERT_TAIL(&cur_fr->certs, cur_cert, list);
		} else
			VTAILQ_INSERT_TAIL(&cfg->certs, cur_cert, list);
		cur_cert = NULL;
	};

SNI_NOMATCH_ABORT_REC : TOK_SNI_NOMATCH_ABORT '=' BOOL {
	cfg->opts->sni_nomatch_abort = $3;
};

CIPHERS_REC: TOK_CIPHERS '=' STRING {
	if ($3)
		REPLACE(cfg->opts->ciphers, $3);
};

CIPHERSUITES_REC: TOK_CIPHERSUITES '=' STRING {
	if ($3)
		REPLACE(cfg->opts->ciphersuites, $3);
};

ECDH_CURVE_REC: TOK_ECDH_CURVE '=' STRING {
	if ($3)
		REPLACE(cfg->opts->ecdh_curve, $3);
};

%%

void
yyerror(struct vtls_cfg *cfg, const char *s)
{
	(void) cfg;
	ARGV_ERR("-A: "
	    "Parsing error in line %d: %s: '%s'\n",
	    yyget_lineno(), s, strlen(vtls_cfg_input_line) > 0 ?
	    vtls_cfg_input_line : "");
}
