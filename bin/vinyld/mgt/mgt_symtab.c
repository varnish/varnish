/*-
 * Copyright (c) 2019 Varnish Software AS
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
 * VCL/VMOD symbol table
 */

#include "config.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "mgt/mgt.h"
#include "mgt/mgt_vcl.h"

#include "vcli_serve.h"
#include "vjsn.h"

/*--------------------------------------------------------------------*/

/*
 * The symbol table may come from an external program, so nothing in it
 * can be trusted: validate everything before acting on any of it.
 */

#define VMOD_CACHE_DIR "./vmod_cache/"

static const char *
mgt_vcl_symtab_val(const struct vjsn_val *vv, const char *val)
{
	const struct vjsn_val *jv;

	jv = vjsn_child(vv, val);
	AN(jv);
	assert(vjsn_is_string(jv));
	AN(jv->value);
	return (jv->value);
}

static int
mgt_vcl_symtab_isstr(const struct vjsn_val *vv, const char *key)
{
	const struct vjsn_val *jv;

	jv = vjsn_child(vv, key);
	return (jv != NULL && vjsn_is_string(jv) && jv->value != NULL);
}

static int
mgt_vcl_check_vmod(const struct vjsn_val *vv, struct vsb *err)
{
	const struct vjsn_val *jv;
	const char *dst;

	jv = vjsn_child(vv, "vext");
	if (jv == NULL || !(vjsn_is_true(jv) || vjsn_is_false(jv))) {
		VSB_cat(err, "Invalid symbol table: "
		    "$VMOD entry without boolean 'vext'\n");
		return (-1);
	}
	if (vjsn_is_true(jv))
		return (0);
	if (!mgt_vcl_symtab_isstr(vv, "name") ||
	    !mgt_vcl_symtab_isstr(vv, "file") ||
	    !mgt_vcl_symtab_isstr(vv, "dst")) {
		VSB_cat(err, "Invalid symbol table: "
		    "$VMOD entry without string 'name', 'file' or 'dst'\n");
		return (-1);
	}
	dst = mgt_vcl_symtab_val(vv, "dst");
	if (strncmp(dst, VMOD_CACHE_DIR, strlen(VMOD_CACHE_DIR)) ||
	    dst[strlen(VMOD_CACHE_DIR)] == '\0' ||
	    strchr(dst + strlen(VMOD_CACHE_DIR), '/') != NULL ||
	    !strcmp(dst + strlen(VMOD_CACHE_DIR), ".") ||
	    !strcmp(dst + strlen(VMOD_CACHE_DIR), "..")) {
		VSB_printf(err, "Invalid symbol table: "
		    "bad VMOD destination '%s'\n", dst);
		return (-1);
	}
	return (0);
}

static int
mgt_vcl_check_vcl(const struct vjsn_val *vv, struct vsb *err)
{
	const struct vclprog *vp2;

	if (!mgt_vcl_symtab_isstr(vv, "name")) {
		VSB_cat(err, "Invalid symbol table: "
		    "$VCL entry without string 'name'\n");
		return (-1);
	}
	vp2 = mcf_vcl_byname(mgt_vcl_symtab_val(vv, "name"));
	if (vp2 == NULL || !mcf_is_label(vp2)) {
		VSB_printf(err, "Invalid symbol table: "
		    "$VCL import of '%s' which is not a label\n",
		    mgt_vcl_symtab_val(vv, "name"));
		return (-1);
	}
	return (0);
}

static int
mgt_vcl_symtab_check(const struct vjsn *vj, struct vsb *err)
{
	const struct vjsn_val *v1, *v2;
	const char *typ;
	int first = 1;

	if (!vjsn_is_array(vj->value)) {
		VSB_cat(err, "Invalid symbol table: not an array\n");
		return (-1);
	}
	VTAILQ_FOREACH(v1, &vj->value->children, list) {
		if (!vjsn_is_object(v1)) {
			VSB_cat(err, "Invalid symbol table: "
			    "element is not an object\n");
			return (-1);
		}
		if (first) {
			first = 0;
			v2 = vjsn_child(v1, "version");
			if (v2 == NULL || !vjsn_is_number(v2) ||
			    v2->value == NULL || strcmp(v2->value, "0")) {
				VSB_cat(err, "Invalid symbol table: "
				    "unsupported or missing version\n");
				return (-1);
			}
		}
		v2 = vjsn_child(v1, "dir");
		if (v2 == NULL)
			continue;
		if (!vjsn_is_string(v2) || v2->value == NULL) {
			VSB_cat(err, "Invalid symbol table: "
			    "'dir' is not a string\n");
			return (-1);
		}
		if (vstrcmp(v2->value, "import"))
			continue;
		if (!mgt_vcl_symtab_isstr(v1, "type")) {
			VSB_cat(err, "Invalid symbol table: "
			    "import entry without string 'type'\n");
			return (-1);
		}
		typ = mgt_vcl_symtab_val(v1, "type");
		if (!vstrcmp(typ, "$VMOD")) {
			if (mgt_vcl_check_vmod(v1, err))
				return (-1);
		} else if (!vstrcmp(typ, "$VCL")) {
			if (mgt_vcl_check_vcl(v1, err))
				return (-1);
		} else {
			VSB_printf(err, "Invalid symbol table: "
			    "unknown import type '%s'\n", typ);
			return (-1);
		}
	}
	if (first) {
		VSB_cat(err, "Invalid symbol table: empty array\n");
		return (-1);
	}
	return (0);
}

static void
mgt_vcl_import_vcl(struct vclprog *vp1, const struct vjsn_val *vv)
{
	struct vclprog *vp2;

	CHECK_OBJ_NOTNULL(vp1, VCLPROG_MAGIC);
	AN(vv);

	vp2 = mcf_vcl_byname(mgt_vcl_symtab_val(vv, "name"));
	CHECK_OBJ_NOTNULL(vp2, VCLPROG_MAGIC);
	mgt_vcl_dep_add(vp1, vp2)->vj = vv;
}

static int
mgt_vcl_cache_vmod(const char *nm, const char *fm, const char *to)
{
	int fi, fo, fl;
	int ret = 0;
	ssize_t sz;
	struct stat st;
	char buf[BUFSIZ];

	fo = open(to, O_WRONLY | O_CREAT | O_EXCL, 0744);
	if (fo < 0 && errno == EEXIST) {
		/* The program may have planted something there */
		if (fstatat(AT_FDCWD, to, &st, AT_SYMLINK_NOFOLLOW) == 0 &&
		    S_ISREG(st.st_mode))
			return (0);
		fprintf(stderr, "While creating copy of vmod %s:\n\t"
		    "%s exists and is not a regular file\n", nm, to);
		return (1);
	}
	if (fo < 0) {
		fprintf(stderr, "While creating copy of vmod %s:\n\t%s: %s\n",
		    nm, to, VAS_errtxt(errno));
		return (1);
	}
	/*
	 * Symlinks are fine (libvcc emits them, for instance through the
	 * vmod_path), but opening must not block and we only copy regular
	 * files.
	 */
	fi = open(fm, O_RDONLY | O_NONBLOCK);
	if (fi < 0) {
		fprintf(stderr, "Opening vmod %s from %s: %s\n",
		    nm, fm, VAS_errtxt(errno));
		(void)unlink(to);
		closefd(&fo);
		return (1);
	}
	if (fstat(fi, &st) || !S_ISREG(st.st_mode)) {
		fprintf(stderr, "Opening vmod %s from %s: not a regular file\n",
		    nm, fm);
		(void)unlink(to);
		closefd(&fi);
		closefd(&fo);
		return (1);
	}
	fl = fcntl(fi, F_GETFL);
	assert(fl != -1);
	AZ(fcntl(fi, F_SETFL, fl & ~O_NONBLOCK));
	while (1) {
		sz = read(fi, buf, sizeof buf);
		if (sz == 0)
			break;
		if (sz < 0 || sz != write(fo, buf, sz)) {
			fprintf(stderr, "Copying vmod %s: %s\n",
			    nm, VAS_errtxt(errno));
			(void)unlink(to);
			ret = 1;
			break;
		}
	}
	closefd(&fi);
	AZ(fchmod(fo, 0444));
	closefd(&fo);
	return (ret);
}

static int
mgt_vcl_import_vmod(struct vclprog *vp, const struct vjsn_val *vv,
    struct vsb *err)
{
	struct vmodfile *vf;
	struct vmoddep *vd;
	const char *v_name;
	const char *v_file;
	const char *v_dst;
	const struct vjsn_val *jv;

	CHECK_OBJ_NOTNULL(vp, VCLPROG_MAGIC);
	AN(vv);

	jv = vjsn_child(vv, "vext");
	AN(jv);
	if (vjsn_is_true(jv))
		return (0);
	v_name = mgt_vcl_symtab_val(vv, "name");
	v_file = mgt_vcl_symtab_val(vv, "file");
	v_dst = mgt_vcl_symtab_val(vv, "dst");

	VTAILQ_FOREACH(vf, &vmodhead, list)
		if (!vstrcmp(vf->fname, v_dst))
			break;
	if (vf == NULL) {
		if (mgt_vcl_cache_vmod(v_name, v_file, v_dst)) {
			VSB_printf(err, "Cannot copy vmod %s from %s to %s\n",
			    v_name, v_file, v_dst);
			return (-1);
		}
		ALLOC_OBJ(vf, VMODFILE_MAGIC);
		AN(vf);
		REPLACE(vf->fname, v_dst);
		VTAILQ_INIT(&vf->vcls);
		VTAILQ_INSERT_TAIL(&vmodhead, vf, list);
	}
	ALLOC_OBJ(vd, VMODDEP_MAGIC);
	AN(vd);
	vd->to = vf;
	VTAILQ_INSERT_TAIL(&vp->vmods, vd, lfrom);
	VTAILQ_INSERT_TAIL(&vf->vcls, vd, lto);
	return (0);
}

/*
 * vjsn_parse() recurses for every nested array or object, so reject deep
 * nesting before handing it untrusted input.
 */

#define SYMTAB_MAXDEPTH 64

static int
mgt_vcl_symtab_depth(const char *p)
{
	int depth = 0, instr = 0;

	for (; *p != '\0'; p++) {
		if (instr) {
			if (*p == '\\' && p[1] != '\0')
				p++;
			else if (*p == '"')
				instr = 0;
			continue;
		}
		switch (*p) {
		case '"':
			instr = 1;
			break;
		case '[':
		case '{':
			if (++depth > SYMTAB_MAXDEPTH)
				return (-1);
			break;
		case ']':
		case '}':
			if (depth > 0)
				depth--;
			break;
		default:
			break;
		}
	}
	return (0);
}

int
mgt_vcl_symtab(struct vclprog *vp, const char *input, struct vsb *err)
{
	struct vjsn *vj;
	struct vjsn_val *v1, *v2;
	const char *typ, *perr;

	CHECK_OBJ_NOTNULL(vp, VCLPROG_MAGIC);
	AN(input);
	AN(err);
	if (mgt_vcl_symtab_depth(input)) {
		VSB_cat(err, "Invalid symbol table: nesting too deep\n");
		return (-1);
	}
	vj = vjsn_parse(input, &perr);
	if (perr != NULL) {
		VSB_printf(err, "Invalid symbol table: parse error: %s\n",
		    perr);
		return (-1);
	}
	AN(vj);
	vp->symtab = vj;
	if (mgt_vcl_symtab_check(vj, err))
		return (-1);

	VTAILQ_FOREACH(v1, &vj->value->children, list) {
		v2 = vjsn_child(v1, "dir");
		if (v2 == NULL || vstrcmp(v2->value, "import"))
			continue;
		typ = mgt_vcl_symtab_val(v1, "type");
		if (!vstrcmp(typ, "$VMOD")) {
			if (mgt_vcl_import_vmod(vp, v1, err))
				return (-1);
		} else {
			assert(!vstrcmp(typ, "$VCL"));
			mgt_vcl_import_vcl(vp, v1);
		}
	}
	return (0);
}

void
mgt_vcl_symtab_clean(struct vclprog *vp)
{

	if (vp->symtab)
		vjsn_delete(&vp->symtab);
}

/*--------------------------------------------------------------------*/

static void
mcf_vcl_vjsn_dump(struct cli *cli, const struct vjsn_val *vj, int indent)
{
	struct vjsn_val *vj1;
	AN(cli);
	AN(vj);

	VCLI_Out(cli, "%*s", indent, "");
	if (vj->name != NULL)
		VCLI_Out(cli, "[\"%s\"]: ", vj->name);
	VCLI_Out(cli, "{%s}", vj->type);
	if (vj->value != NULL)
		VCLI_Out(cli, " <%s>", vj->value);
	VCLI_Out(cli, "\n");
	VTAILQ_FOREACH(vj1, &vj->children, list)
		mcf_vcl_vjsn_dump(cli, vj1, indent + 2);
}

void v_matchproto_(cli_func_t)
mcf_vcl_symtab(struct cli *cli, const char * const *av, void *priv)
{
	struct vclprog *vp;
	struct vcldep *vd;

	(void)av;
	(void)priv;
	VTAILQ_FOREACH(vp, &vclhead, list) {
		if (mcf_is_label(vp))
			VCLI_Out(cli, "Label: %s\n", vp->name);
		else
			VCLI_Out(cli, "Vcl: %s\n", vp->name);
		if (!VTAILQ_EMPTY(&vp->dfrom)) {
			VCLI_Out(cli, "  imports from:\n");
			VTAILQ_FOREACH(vd, &vp->dfrom, lfrom) {
				VCLI_Out(cli, "    %s\n", vd->to->name);
				if (vd->vj)
					mcf_vcl_vjsn_dump(cli, vd->vj, 6);
			}
		}
		if (!VTAILQ_EMPTY(&vp->dto)) {
			VCLI_Out(cli, "  exports to:\n");
			VTAILQ_FOREACH(vd, &vp->dto, lto) {
				VCLI_Out(cli, "    %s\n", vd->from->name);
				if (vd->vj)
					mcf_vcl_vjsn_dump(cli, vd->vj, 6);
			}
		}
		if (vp->symtab != NULL) {
			VCLI_Out(cli, "  symtab:\n");
			mcf_vcl_vjsn_dump(cli, vp->symtab->value, 4);
		}
	}
}

/*--------------------------------------------------------------------*/

static void
mcf_vcl_vjsn_json(struct cli *cli, const struct vjsn_val *vj)
{
	struct vjsn_val *vj1;
	const char *sep = "";

	AN(cli);
	CHECK_OBJ_NOTNULL(vj, VJSN_VAL_MAGIC);

	if (vjsn_is_string(vj)) {
		VCLI_JSON_str(cli, vj->value);
		return;
	}
	if (vjsn_is_number(vj)) {
		VCLI_Out(cli, "%s", vj->value);
		return;
	}
	if (!vjsn_is_object(vj) && !vjsn_is_array(vj)) {
		/* true, false, null */
		VCLI_Out(cli, "%s", vj->type);
		return;
	}
	VCLI_Out(cli, "%c", vjsn_is_object(vj) ? '{' : '[');
	VSB_indent(cli->sb, 2);
	VTAILQ_FOREACH(vj1, &vj->children, list) {
		VCLI_Out(cli, "%s\n", sep);
		if (vj1->name != NULL) {
			VCLI_JSON_str(cli, vj1->name);
			VCLI_Out(cli, ": ");
		}
		mcf_vcl_vjsn_json(cli, vj1);
		sep = ",";
	}
	VSB_indent(cli->sb, -2);
	if (*sep != '\0')
		VCLI_Out(cli, "\n");
	VCLI_Out(cli, "%c", vjsn_is_object(vj) ? '}' : ']');
}

static void
mcf_vcl_symtab_dep_json(struct cli *cli, const struct vclprog *vp,
    const struct vjsn_val *vj, const char *sep)
{

	CHECK_OBJ_NOTNULL(vp, VCLPROG_MAGIC);
	VCLI_Out(cli, "%s\n", sep);
	VCLI_Out(cli, "{\n");
	VSB_indent(cli->sb, 2);
	VCLI_Out(cli, "\"name\": ");
	VCLI_JSON_str(cli, vp->name);
	VCLI_Out(cli, ",\n");
	VCLI_Out(cli, "\"entry\": ");
	if (vj != NULL)
		mcf_vcl_vjsn_json(cli, vj);
	else
		VCLI_Out(cli, "null");
	VCLI_Out(cli, "\n");
	VSB_indent(cli->sb, -2);
	VCLI_Out(cli, "}");
}

void v_matchproto_(cli_func_t)
mcf_vcl_symtab_json(struct cli *cli, const char * const *av, void *priv)
{
	struct vclprog *vp;
	struct vcldep *vd;
	const char *sep;

	(void)priv;
	VCLI_JSON_begin(cli, 1, av);
	VTAILQ_FOREACH(vp, &vclhead, list) {
		VCLI_Out(cli, ",\n");
		VCLI_Out(cli, "{\n");
		VSB_indent(cli->sb, 2);
		VCLI_Out(cli, "\"name\": ");
		VCLI_JSON_str(cli, vp->name);
		VCLI_Out(cli, ",\n");
		VCLI_Out(cli, "\"label\": %s,\n",
		    mcf_is_label(vp) ? "true" : "false");

		VCLI_Out(cli, "\"imports\": [");
		VSB_indent(cli->sb, 2);
		sep = "";
		VTAILQ_FOREACH(vd, &vp->dfrom, lfrom) {
			mcf_vcl_symtab_dep_json(cli, vd->to, vd->vj, sep);
			sep = ",";
		}
		VSB_indent(cli->sb, -2);
		VCLI_Out(cli, "%s", *sep ? "\n" : "");
		VCLI_Out(cli, "],\n");

		VCLI_Out(cli, "\"exports\": [");
		VSB_indent(cli->sb, 2);
		sep = "";
		VTAILQ_FOREACH(vd, &vp->dto, lto) {
			mcf_vcl_symtab_dep_json(cli, vd->from, vd->vj, sep);
			sep = ",";
		}
		VSB_indent(cli->sb, -2);
		VCLI_Out(cli, "%s", *sep ? "\n" : "");
		VCLI_Out(cli, "],\n");

		VCLI_Out(cli, "\"symtab\": ");
		if (vp->symtab != NULL)
			mcf_vcl_vjsn_json(cli, vp->symtab->value);
		else
			VCLI_Out(cli, "null");
		VCLI_Out(cli, "\n");
		VSB_indent(cli->sb, -2);
		VCLI_Out(cli, "}");
	}
	VCLI_JSON_end(cli);
}
