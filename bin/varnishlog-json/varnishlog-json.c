/*-
 * Copyright (c) 2024 Varnish Software AS
 * All rights reserved.
 *
 * Author: Guillaume Quintard <guillaume.quintard@varnish-software.com>
 * Author: Darryl Rodden <darryl.rodden@varnish-software.com>
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
 * JSON Log tailer for Varnish
 */

#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VOPT_DEFINITION
#define VOPT_INC "varnishlog-json_options.h"

#include "miniobj.h"
#include "vdef.h"
#include "vapi/vsl.h"
#include "vapi/voptget.h"
#include "vas.h"
#include "vsb.h"
#include "vut.h"

#include "cJSON.h"

#define GROUP_MODES()			\
	GROUP_MODE(probe, raw)		\
	GROUP_MODE(request, request)	\
	GROUP_MODE(vxid, vxid)

struct group_mode {
	const char	*name;
	const char	*vsl_group;
};

#define GROUP_MODE(nm, vsl)				\
static const struct group_mode *const mode_##nm =	\
    &(struct group_mode){ #nm, #vsl };
GROUP_MODES()
#undef GROUP_MODE

static struct VUT *vut;

static struct {
	/* Options */
	int			a_opt;
	char			*w_arg;
	const struct group_mode	*mode;
	unsigned		pretty;

	/* State */
	FILE			*fo;
	struct vsb		*vsb;
} CTX;

/* Returns a pointer to the first occurrence of character 'c' found in string
 * 's', offset by 'offset' characters. If the resulting pointer would point
 * outside of 's' NULL is returned.
 */
static const char *
strchr_offset(const char *s, char c, int offset)
{
	const char *ptr;

	AN(s);

	ptr = strchr(s, c);
	if (ptr == NULL)
		return (NULL);

	if ((offset < 0 && ptr + offset < s) ||
	    (offset > 0 && strnlen(ptr, offset) < offset))
		return (NULL);

	return (ptr + offset);
}

static inline const char*
tok_init(const char *s)
{
	AN(s);
	return (s);
}

static inline ssize_t
tok_curr(const char **p)
{
	const char *b;
	const char *e;

	AN(p);
	AN(*p);

	/* skip whitespace to find the beginning of the token */
	b = *p;
	while (isspace(*b))
		b++;
	if (*b == '\0')
		return (0);

	/* find the end of the token (a whitespace or '\0') */
	e = b + 1;
	while (*e && !isspace(*e))
		e++;

	/* return the beginning of the token and length */
	*p = b;
	return (e - b);
}

static inline ssize_t
tok_skip(const char **p)
{
	ssize_t len;

	/* skip past current token. len could be 0 if we reach EOL. */
	len = tok_curr(p);
	*p += len;
	return (len);
}

static inline ssize_t
tok_get(const char **p)
{
	ssize_t len;

	VSB_clear(CTX.vsb);

	len = tok_curr(p);
	if (len != 0) {
		VSB_bcat(CTX.vsb, *p, len);
		VSB_finish(CTX.vsb);
		*p += len;	/* skip past current token */
	}

	return (len);
}

static void
replaceString(cJSON *object, const char *field, const char *value)
{
	cJSON *temp_s;

	if (cJSON_GetObjectItemCaseSensitive(object, field)) {
		temp_s = cJSON_CreateString(value);
		AN(temp_s);
		AN(cJSON_ReplaceItemInObjectCaseSensitive(object, field, temp_s));
	} else {
		AN(cJSON_AddStringToObject(object, field, value));
	}
}

static void
add_hdr(const char *s, cJSON *resp, cJSON *hdrs)
{
	cJSON *temp_a, *temp_s;
	const char *c, *sep;
	char *p;

	AN(s);
	AN(hdrs);

	/* allow the first char to be ':'. H/2?  Will we see this? */
	if (*s == ':')
		s++;
	c = strchr(s, ':');
	if (c == NULL)		/* is no ':' an error? */
		c = strchr(s, '\0');

	/* stash and lowercase the header name */
	AN(c);
	VSB_clear(CTX.vsb);
	VSB_bcat(CTX.vsb, s, c - s);
	VSB_finish(CTX.vsb);
	for (p = VSB_data(CTX.vsb); *p; p++)
		*p = tolower(*p);

	/* skip past ':' and find the beginning of the header value */
	if (*c == ':')
		c++;
	while (isspace(*c))
		c++;

	if (resp != NULL && strcmp(VSB_data(CTX.vsb), "set-cookie") == 0) {
		temp_a = cJSON_GetObjectItemCaseSensitive(resp, "set-cookie");
		if (temp_a == NULL)
			temp_a = cJSON_AddArrayToObject(resp, "set-cookie");
		AN(temp_a);
		temp_s = cJSON_CreateString(c);
		AN(temp_s);
		AN(cJSON_AddItemToArray(temp_a, temp_s));
		return;
	}

	temp_a = cJSON_GetObjectItemCaseSensitive(hdrs, VSB_data(CTX.vsb));
	if (temp_a != NULL) {
		sep = strcmp(VSB_data(CTX.vsb), "cookie") == 0 ? ";" : ",";
		VSB_clear(CTX.vsb);
		VSB_printf(CTX.vsb, "%s%s%s", cJSON_GetStringValue(temp_a), sep, c);
		VSB_finish(CTX.vsb);
		AN(cJSON_SetValuestring(temp_a, VSB_data(CTX.vsb)));
	} else
		AN(cJSON_AddStringToObject(hdrs, VSB_data(CTX.vsb), c));
}

static ssize_t
backend_name(const char *tok)
{
	const char *end;

	AN(tok);

	VSB_clear(CTX.vsb);

	/* Skip VCL name */
	tok = strchr_offset(tok, '.', 1);
	AN(tok);

	if (strncmp(tok, "udo.", strlen("udo.")) == 0 ||
	    strncmp(tok, "s3.", strlen("s3.")) == 0) {
		/* Use director name as backend name */
		tok = strchr_offset(tok, '.', 1);
		AN(tok);
		end = strchr(tok, '.');
		AN(end);
		VSB_bcat(CTX.vsb, tok, end - tok);
		VSB_finish(CTX.vsb);
	} else if (strncmp(tok, "goto.", strlen("goto.")) == 0) {
		/* goto backends don't have a director name */
		VSB_bcat(CTX.vsb, "goto", strlen("goto."));
		VSB_finish(CTX.vsb);
	} else {
		/* Static backend, just use the rest of the token */
		tok_get(&tok);
	}
	return (VSB_len(CTX.vsb));
}

static void
openout(int append)
{
	AN(CTX.w_arg);
	if (!strcmp(CTX.w_arg, "-"))
		CTX.fo = stdout;
	else
		CTX.fo = fopen(CTX.w_arg, append ? "a" : "w");
	if (CTX.fo == NULL)
		VUT_Error(vut, 2, "Cannot open output file (%s)", strerror(errno));
	vut->dispatch_priv = CTX.fo;
}

static int v_matchproto_(VUT_cb_f)
rotateout(struct VUT *v)
{

	assert(v == vut);
	AN(CTX.w_arg);
	AN(CTX.fo);
	(void)fclose(CTX.fo);
	openout(1);
	AN(CTX.fo);
	return (0);
}

static int v_matchproto_(VUT_cb_f)
flushout(struct VUT *v)
{

	assert(v == vut);
	AN(CTX.fo);
	if (fflush(CTX.fo))
		return (-5);
	return (0);
}

static int
process_probe(struct VSL_data *vsl,
    struct VSL_transaction * const trans[], void *priv)
{
	enum vsl_status i;
	cJSON *t= NULL;
	double duration;
	enum VSL_tag_e tag;
	const char *c, *e = NULL;
	char buf[4096];
	struct VSL_transaction *tp = NULL;

	(void)vsl;
	(void)priv;

	AN(trans);
	AN(trans[0]);
	AZ(trans[1]);
	tp = trans[0];

	i = VSL_Next(tp->c);
	if (i < vsl_end)
		return (i);	/* error */
	assert (i != vsl_end);

	tag = VSL_TAG(tp->c->rec.ptr);
	if (tag != SLT_Backend_health)
		return (0);

	t = cJSON_CreateObject();
	AN(t);

	c = tok_init(VSL_CDATA(tp->c->rec.ptr));
	AN(tok_get(&c));
	AN(cJSON_AddStringToObject(t, "backend", VSB_data(CTX.vsb)));
	AN(tok_skip(&c));
	AN(tok_get(&c));
	if (strcmp(VSB_data(CTX.vsb), "healthy")) {
		AN(cJSON_AddBoolToObject(t, "healthy", false));
	} else {
		AN(cJSON_AddBoolToObject(t, "healthy", true));
	}
	AN(tok_get(&c));
	assert(VSB_len(CTX.vsb) == 8);
	if (VSB_data(CTX.vsb)[7] == 'H') {
		AN(cJSON_AddBoolToObject(t, "happy", true));
	} else {
		AN(cJSON_AddBoolToObject(t, "happy", false));
	}
	AN(cJSON_AddStringToObject(t, "report", VSB_data(CTX.vsb)));

	AN(tok_skip(&c));
	AN(tok_skip(&c));
	AN(tok_skip(&c));
	AN(tok_get(&c));
	duration = strtod(VSB_data(CTX.vsb), NULL);
	AN(cJSON_AddNumberToObject(t, "duration", duration));

	AN(tok_skip(&c));
	while (!isspace(*c)) {
		c++;
	}
	c++;
	AN(cJSON_AddStringToObject(t, "message", c));
	// Open-source change: we need to unwrap the quotes, if any
	if (*c == '"') {
		c++;
		e = strchr(c, '"');
		if (e != NULL) {
			if (e - c >= sizeof(buf)) {
				e = c + sizeof(buf) - 1;
			}
			strncpy(buf, c, e - c);
			buf[e - c] = '\0';
			AN(cJSON_AddStringToObject(t, "message", buf));
		} else {
			AN(cJSON_AddStringToObject(t, "message", c));
		}
	} else {
		AN(cJSON_AddStringToObject(t, "message", c));
	}

	AZ(VSL_Next(tp->c));

	char *s;
	if (CTX.pretty)
		s = cJSON_Print(t);
	else
		s = cJSON_PrintUnformatted(t);
	AN(s);
	printf("%s\n", s);
	free(s);
	cJSON_Delete(t);

	return (0);
}

static enum vsl_status
process_vsl_transaction(struct VSL_transaction *t, struct VSL_data *vsl,
    cJSON *transaction_array)
{
	int l;
	enum vsl_status i;
	enum VSL_tag_e tag;
	bool req_done, resp_done;
	const char *c, *data, *handling = "incomplete";
	cJSON *transaction, *timeline;
	cJSON *req, *req_hdrs, *req_hdrs_tmp;
	cJSON *resp, *resp_hdrs, *resp_hdrs_tmp;
	cJSON *temp_s, *temp_a;
	cJSON *links, *link;
	cJSON *backend, *client;
	cJSON *ts, *h;
	char *p;
	unsigned _a, _e, _f;
	float _b, _c, _d;
	double status;
	int req_hdr_len, req_body_len, resp_hdr_len, resp_body_len, l1, l2;

	AN(t);
	AN(vsl);
	AN(transaction_array);
	assert(t->type == VSL_t_req || t->type == VSL_t_bereq);

	transaction = cJSON_CreateObject();
	AN(transaction);
	AN(cJSON_AddItemToArray(transaction_array, transaction));

	if (t->type == VSL_t_req)
		AN(cJSON_AddStringToObject(transaction, "side", "client"));
	else
		AN(cJSON_AddStringToObject(transaction, "side", "backend"));

	req = cJSON_AddObjectToObject(transaction, "req");
	req_hdrs = cJSON_AddObjectToObject(req, "headers");
	req_hdrs_tmp = cJSON_AddObjectToObject(req, "headers_tmp");

	resp = cJSON_AddObjectToObject(transaction, "resp");
	resp_hdrs = cJSON_AddObjectToObject(resp, "headers");
	resp_hdrs_tmp = cJSON_AddObjectToObject(resp, "headers_tmp");

	timeline = cJSON_AddArrayToObject(transaction, "timeline");

	req_done = false;
	resp_done = false;

	/* loop through all vsl records in the transaction */
	while (1) {
		i = VSL_Next(t->c);
		if (i < vsl_end)
			return (i);	/* error */
		if (i == vsl_end)
			break;

		/* -i/-I check, notably */
		if (!VSL_Match(vsl, t->c))
			continue;

		tag = VSL_TAG(t->c->rec.ptr);
		data = VSL_CDATA(t->c->rec.ptr);

		switch (tag) {
		case SLT_Begin:
			VSB_clear(CTX.vsb);
			VSB_printf(CTX.vsb, "%jd", (intmax_t)t->vxid);
			VSB_finish(CTX.vsb);
			AN(cJSON_AddStringToObject(transaction,
			    "id", VSB_data(CTX.vsb)));
			break;

		case SLT_VCL_call:
			if (t->type == VSL_t_req)
				req_done = true;
			else if (!strcmp(data, "BACKEND_RESPONSE") ||
				!strcmp(data, "BACKEND_ERROR"))
				resp_done = true;

			/*
			 * don't overwrite handling if we're already erroring
			 * we don't need to handle HIT, SLT_Hit will take care of it
			 */
			if (!strcmp(handling, "fail") || !strcmp(handling, "abandon"))
				break;

			if (!strcmp(data, "MISS"))
				handling = "miss";
			else if (!strcmp(data, "PASS"))
				handling = "pass";
			else if (!strcmp(data, "PIPE"))
				handling = "pipe";
			else if (!strcmp(data, "SYNTH"))
				handling = "synth";
			else if (!strcmp(data, "BACKEND_RESPONSE"))
				handling = "fetch";
			else if (!strcmp(data, "BACKEND_ERROR"))
				handling = "error";
			else if (!strcmp(data, "SYNTH"))
				handling = "synth";
			break;

		case SLT_Hit:
			if (!strcmp(handling, "fail") || !strcmp(handling, "abandon"))
				break;

			l = sscanf(data, "%u %f %f %f %u %u",
			    &_a, &_b, &_c, &_d, &_e, &_f);

			if (l == 6)
				handling = "streaming-hit";
			else
				handling = "hit";
			break;

		case SLT_VCL_return:
			if (t->type == VSL_t_bereq &&
			   (!strcmp(data, "fetch") || !strcmp(data, "error")))
				req_done = true;

			if (!strcmp(data, "fail"))
				handling = "fail";
			else if (!strcmp(data, "abandon"))
				handling = "abandon";
			break;

#define save_data(tag, cond, obj, field, s) 	\
case tag:					\
	if (cond)				\
		replaceString(obj, field, s);	\
	break;					\

		save_data(SLT_ReqMethod, !req_done, req, "method", data);
		save_data(SLT_BereqMethod, !req_done, req, "method", data);

		save_data(SLT_ReqProtocol, !req_done, req, "proto", data);
		save_data(SLT_BereqProtocol, !req_done, req, "proto", data);

		save_data(SLT_ReqURL, !req_done, req, "url", data);
		save_data(SLT_BereqURL, !req_done, req, "url", data);

		save_data(SLT_RespReason, !resp_done, resp, "reason", data);
		save_data(SLT_BerespReason, !resp_done, resp, "reason", data);

		save_data(SLT_RespProtocol, !resp_done, resp, "proto", data);
		save_data(SLT_BerespProtocol, !resp_done, resp, "proto", data);

		save_data(SLT_VCL_use, true, transaction, "vcl", data);

		save_data(SLT_Storage, true, transaction, "storage", data);

		case SLT_RespStatus:
		case SLT_BerespStatus:
			status = strtod(data, NULL);
			/* Varnish won't accept them, we shouldn't either */
			assert(status > 0);
			assert(status < 1000);
			assert(status == round(status));
			if (!resp_done)
				AN(cJSON_AddNumberToObject(resp, "status", status));
			break;

		case SLT_ReqHeader:
		case SLT_BereqHeader:
			if (!req_done)
				AN(cJSON_AddBoolToObject(req_hdrs_tmp, data, 1));
			break;

		case SLT_RespHeader:
		case SLT_BerespHeader:
			if (!resp_done)
				AN(cJSON_AddBoolToObject(resp_hdrs_tmp, data, 1));
			break;

		case SLT_ReqUnset:
		case SLT_BereqUnset:
			if (!req_done)
				cJSON_DeleteItemFromObject(req_hdrs_tmp, data);
			break;

		case SLT_RespUnset:
		case SLT_BerespUnset:
			if (!resp_done)
				cJSON_DeleteItemFromObject(resp_hdrs_tmp, data);
			break;

		case SLT_ReqAcct:
		case SLT_BereqAcct:
			/*
			 * we don't care about l1 and l2, but we might as
			 * well just read everything as a sanity check.
			 */
			l = sscanf(data, "%i %i %i %i %i %i",
			    &req_hdr_len, &req_body_len, &l1,
			    &resp_hdr_len, &resp_body_len, &l2);
			assert(l == 6);
			AN(cJSON_AddNumberToObject(req, "hdrBytes", req_hdr_len));
			AN(cJSON_AddNumberToObject(req, "bodyBytes", req_body_len));
			AN(cJSON_AddNumberToObject(resp, "hdrBytes", resp_hdr_len));
			AN(cJSON_AddNumberToObject(resp, "bodyBytes", resp_body_len));
			break;

		case SLT_VCL_Log:
			temp_s = cJSON_CreateString(data);
			AN(temp_s);
			temp_a = cJSON_GetObjectItemCaseSensitive(transaction, "logs");
			if (!temp_a) {
				temp_a = cJSON_AddArrayToObject(transaction, "logs");
			}
			AN(temp_a);
			AN(cJSON_AddItemToArray(temp_a, temp_s));
			break;

		case SLT_Error:
		case SLT_FetchError:
		case SLT_VCL_Error:
			temp_s = cJSON_CreateString(data);
			AN(temp_s);
			temp_a = cJSON_GetObjectItemCaseSensitive(transaction, "errors");
			if (!temp_a) {
				temp_a = cJSON_AddArrayToObject(transaction, "errors");
			}
			AN(temp_a);
			AN(cJSON_AddItemToArray(temp_a, temp_s));
			break;

		case SLT_Link:
			links = cJSON_GetObjectItemCaseSensitive(transaction, "links");
			if (!links)
				links = cJSON_AddArrayToObject(transaction, "links");
			AN(links);
			link = cJSON_CreateObject();
			AN(link);
			c = tok_init(data);
			AN(tok_get(&c));
			AN(cJSON_AddStringToObject(link, "type", VSB_data(CTX.vsb)));
			AN(tok_get(&c));
			AN(cJSON_AddStringToObject(link, "id", VSB_data(CTX.vsb)));
			AN(tok_get(&c));
			AN(cJSON_AddStringToObject(link, "reason", VSB_data(CTX.vsb)));

			AN(cJSON_AddItemToArray(links, link));
			break;

		case SLT_Timestamp:
			ts = cJSON_CreateObject();
			AN(ts);
			c = tok_init(data);
			AN(tok_get(&c));
			p = VSB_len(CTX.vsb) ? VSB_data(CTX.vsb) + VSB_len(CTX.vsb) - 1 : NULL;
			if (p != NULL) {
				assert(*p == ':');
				*p = '\0';
			}
			AN(cJSON_AddStringToObject(ts, "name", VSB_data(CTX.vsb)));

			/*
			 * float conversion is a mess, so we just grab the timestamp as-is,
			 * copy it to a buffer, null-terminated and pass it raw to cJSON.
			 */
			AN(tok_get(&c));
			AN(cJSON_AddRawToObject(ts, "timestamp", VSB_data(CTX.vsb)));

			AN(cJSON_AddItemToArray(timeline, ts));
			break;

		case SLT_BackendOpen:
			backend = cJSON_AddObjectToObject(transaction, "backend");
			AN(backend);
			c = tok_init(data);
			// skip the file descriptor
			AN(tok_skip(&c));
			// Parse out backend/director name and skip the rest
			AN(backend_name(c));
			AN(tok_skip(&c));
			AN(cJSON_AddStringToObject(backend, "name", VSB_data(CTX.vsb)));
			AN(tok_get(&c));
			AN(cJSON_AddStringToObject(backend, "rAddr", VSB_data(CTX.vsb)));
			AN(tok_get(&c));
			AN(cJSON_AddRawToObject(backend, "rPort", VSB_data(CTX.vsb)));
			AN(tok_skip(&c));
			AN(tok_skip(&c));
			AN(tok_get(&c));
			AN(cJSON_AddBoolToObject(backend, "connReused",
			    strcmp(VSB_data(CTX.vsb), "reuse") ? 0 : 1));
			break;

		case SLT_ReqStart:
			client = cJSON_AddObjectToObject(transaction, "client");
			AN(client);
			c = tok_init(data);
			AN(tok_get(&c));
			AN(cJSON_AddStringToObject(client, "rAddr", VSB_data(CTX.vsb)));
			AN(tok_get(&c));
			AN(cJSON_AddRawToObject(client, "rPort", VSB_data(CTX.vsb)));
			AN(tok_get(&c));
			AN(cJSON_AddStringToObject(client, "sock", VSB_data(CTX.vsb)));
			break;

		case SLT_End:
			if (!strcmp(data, "synth"))
				replaceString(transaction, "error", "truncated log");
			break;
		default:
			break;
		}
	}

	AN(cJSON_AddStringToObject(transaction, "handling", handling));

	/* go through the flattened headers to put them in an object */
	cJSON_ArrayForEach(h, req_hdrs_tmp)
		add_hdr(h->string, NULL, req_hdrs);
	cJSON_DeleteItemFromObject(req, "headers_tmp");

	cJSON_ArrayForEach(h, resp_hdrs_tmp)
		add_hdr(h->string, resp, resp_hdrs);
	cJSON_DeleteItemFromObject(resp, "headers_tmp");

	return (vsl_end);
}

static int process_group(struct VSL_data *vsl,
    struct VSL_transaction * const trans[], void *priv)
{
	enum vsl_status i;
	char *s;
	cJSON *obj;
	cJSON *transaction_array;

	transaction_array = cJSON_CreateArray();
	AN(transaction_array);
	(void)priv;

	for (struct VSL_transaction *t = trans[0]; t != NULL; t = *++trans) {
		if (t->type != VSL_t_req && t->type != VSL_t_bereq)
			continue;

		i = process_vsl_transaction(t, vsl, transaction_array);

		if (i < vsl_end) {
			cJSON_Delete(transaction_array);
			return (i);	/* error */
		}

		if (CTX.mode != mode_request)
			break;
	}

	if (cJSON_GetArraySize(transaction_array) == 0) {
		cJSON_Delete(transaction_array);
		return (0);
	}

	if (CTX.mode == mode_request)
		obj = transaction_array;
	else
		obj = cJSON_GetArrayItem(transaction_array, 0);
	AN(obj);

	if (CTX.pretty)
		s = cJSON_Print(obj);
	else
		s = cJSON_PrintUnformatted(obj);
	AN(s);
	printf("%s\n", s);
	free(s);
	cJSON_Delete(transaction_array);

	return (0);
}

static void v_noreturn_
usage(int status)
{
	const char **opt;
	fprintf(stderr, "Usage: %s <options>\n\n", vut->progname);
	fprintf(stderr, "Options:\n");
	for (opt = vopt_spec.vopt_usage; *opt != NULL; opt += 2)
		fprintf(stderr, " %-25s %s\n", *opt, *(opt + 1));
	exit(status);
}

int
main(int argc, char **argv)
{
	int opt;
	bool bc_set = false;

	vut = VUT_InitProg(argc, argv, &vopt_spec);
	CTX.mode = mode_vxid;

	while ((opt = getopt(argc, argv, vopt_spec.vopt_optstring)) != -1) {
		switch (opt) {
		case 'a':
			CTX.a_opt = 1;
			break;
		case 'b':
		case 'c':
			bc_set = true;
			AN(VUT_Arg(vut, opt, NULL));
			break;
		case 'g':
#define GROUP_MODE(nm, vsl)				\
			if (!strcmp(#nm, optarg)) {	\
				CTX.mode = mode_##nm;	\
				break;			\
			}
			GROUP_MODES()
#undef GROUP_MODE
			fprintf(stderr,
			    "Error: unknown -g argument \"%s\"\n\n", optarg);
			usage(1);
			break;
		case 'h':
			usage(0);
			break;
		case 'p':
			CTX.pretty = 1;
			break;
		case 'w':
			REPLACE(CTX.w_arg, optarg);
			break;
		default:
			if (!VUT_Arg(vut, opt, optarg))
				usage(1);
		}

	}

	VUT_Arg(vut, 'g', CTX.mode->vsl_group);

	if (!bc_set && CTX.mode == mode_vxid)
		AN(VUT_Arg(vut, 'c', NULL));

	if (optind != argc)
		usage(1);

	if (vut->D_opt && !CTX.w_arg)
		VUT_Error(vut, 1, "Missing -w option");

	if (vut->D_opt && !strcmp(CTX.w_arg, "-"))
		VUT_Error(vut, 1, "Daemon cannot write to stdout");

	if (CTX.w_arg) {
		openout(CTX.a_opt);
		AN(CTX.fo);
		if (vut->D_opt)
			vut->sighup_f = rotateout;
	} else
		CTX.fo = stdout;

	if (CTX.mode == mode_probe) {
		vut->dispatch_f = process_probe;
	} else {
		vut->dispatch_f = process_group;
	}
	vut->idle_f = flushout;

	/* prepare, loop forever (or until told to stop), then clean up */
	CTX.vsb = VSB_new_auto();
	AN(CTX.vsb);

	VUT_Setup(vut);
	(void)VUT_Main(vut);
	VUT_Fini(&vut);

	VSB_destroy(&CTX.vsb);

	(void)flushout(NULL);
	return (0);
}
