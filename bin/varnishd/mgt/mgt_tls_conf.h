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
 * Manager process TLS configuration
 */

#ifdef MGT_TLS_CONF_H_INCLUDED
#  error "mgt_tls_conf.h included multiple times"
#endif
#define MGT_TLS_CONF_H_INCLUDED

#include "vqueue.h"
#include "common/common_vtls_types.h"

/*
 * Temporary structs used in parsing a VTLS config file
 */

struct vtls_cert_cfg {
	unsigned		magic;
#define VTLS_CERT_CFG_MAGIC	0x36d730d4
	char			*cert;
	char			*priv;
	char			*dhparam;
	char			*ciphers;
	char			*ciphersuites;
	int			protos;
	char			*id;

	VTAILQ_ENTRY(vtls_cert_cfg) list;
};

struct vtls_frontend_cfg {
	unsigned			magic;
#define VTLS_FRONTEND_CFG_MAGIC		0xba4ccdcb
	char				*host;
	char				*port;
	char				*argspec;
	char				*name;
	int 				sni_match_global;
	struct vtls_cfg_opts		opts[1];
	VTAILQ_HEAD(, vtls_cert_cfg)	certs;
	VTAILQ_ENTRY(vtls_frontend_cfg)	list;
};

struct vtls_cfg {
	unsigned				magic;
#define VTLS_CFG_MAGIC				0x5500582c
	VTAILQ_HEAD(, vtls_frontend_cfg)	frontends;
	VTAILQ_HEAD(, vtls_cert_cfg)		certs;
	struct vtls_cfg_opts			opts[1];
};

/* Manager TLS configuration functions */
struct vtls_frontend_cfg *VTLS_frontend_cfg_alloc(void);
int TLS_Config(const char *fn);
int MGT_TLS_push_server_certs(unsigned *status, char **p);
void MGT_TLS_Init(void);
void *TLS_Listener_Config(void);
