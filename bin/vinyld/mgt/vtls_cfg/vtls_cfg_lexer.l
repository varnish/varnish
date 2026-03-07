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
 * TLS config file lexer
 */

#include <string.h>
#include "mgt/mgt_tls_conf.h"
#include "vtls_cfg_parser.h"

char vtls_cfg_input_line[512];
%}

%option nounput noinput
%option yylineno
%option noyywrap
%%
\n.* {
	strncpy(vtls_cfg_input_line, yytext + 1, sizeof (vtls_cfg_input_line) - 1);
	vtls_cfg_input_line[sizeof(vtls_cfg_input_line) - 1] = '\0';
	yyless(1);
}

[ \t\n\r]	;
#.*$		;
"{"		{ return ('{'); }
"}"		{ return ('}'); }
"="		{ return ('='); }

[0-9]+ {
	yylval.i = atoi(yytext);
	return (UINT);
}

\-?[0-9]+ {
	yylval.i = atoi(yytext);
	return (INT);
}

"frontend"			{ return (TOK_FRONTEND); }
"tls-protos"			{ return (TOK_TLS_PROTOS); }
"SSLv3"				{ return (TOK_SSLv3); }
"TLSv1.0"			{ return (TOK_TLSv1_0); }
"TLSv1.1"			{ return (TOK_TLSv1_1); }
"TLSv1.2"			{ return (TOK_TLSv1_2); }
"TLSv1.3"			{ return (TOK_TLSv1_3); }
"ciphers"			{ return (TOK_CIPHERS); }
"ciphersuites"			{ return (TOK_CIPHERSUITES); }
"prefer-server-ciphers"		{ return (TOK_PREFER_SERVER_CIPHERS); }
"sni-nomatch-abort"		{ return (TOK_SNI_NOMATCH_ABORT); }
"host"				{ return (TOK_HOST); }
"port"				{ return (TOK_PORT); }
"match-global-certs"		{ return (TOK_MATCH_GLOBAL); }
"cert"				{ return (TOK_PB_CERT); }
"pem-file"			{ return (TOK_PEM_FILE); }
"private-key"			{ return (TOK_PRIVATE_KEY); }
"dhparam"			{ return (TOK_DHPARAM); }
"ecdh-curve"			{ return (TOK_ECDH_CURVE); }
"name"				{ return (TOK_NAME); }

(?i:"yes"|"y"|"on"|"true"|"t"|\"yes\"|\"y\"|\"on\"|\"true\"|\"t\") {
	yylval.i = 1;
	return (BOOL);
}

(?i:"no"|"n"|"off"|"false"|"f"|\"no\"|\"n\"|\"off\"|\"false\"|\"f\") {
	yylval.i = 0;
	return (BOOL);
}

\"(\\.|[^\\"])*\" {
	char *s;
	if (strlen(yytext) == 2) {
		yylval.s = NULL;
		return (STRING);
	}
	s = strchr(yytext + 1, '"');
	*s = '\0';
	yylval.s = yytext + 1;
	return (STRING);
}

[a-zA-Z0-9\-]+ {
	yylval.s = yytext;
	return (STRING);
}

. ;
%%
