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
	AN(vjsn_is_string(jv));
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
mgt_vcl_check_vcl(const struct vclprog *vp, const struct vjsn_val *vv,
    struct vsb *err)
{
	const struct vclprog *vp2;

	if (!mgt_vcl_symtab_isstr(vv, "name")) {
		VSB_cat(err, "Invalid symbol table: "
		    "$VCL entry without string 'name'\n");
		return (-1);
	}
	vp2 = mcf_vcl_byname(mgt_vcl_symtab_val(vv, "name"));
	if (vp2 == NULL || vp2 == vp) {
		VSB_printf(err, "Invalid symbol table: "
		    "import of unknown VCL '%s'\n",
		    mgt_vcl_symtab_val(vv, "name"));
		return (-1);
	}
	return (0);
}

static int
mgt_vcl_symtab_check(const struct vclprog *vp, const struct vjsn *vj,
    struct vsb *err)
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
			if (mgt_vcl_check_vcl(vp, v1, err))
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
	int fi, fo;
	int ret = 0;
	ssize_t sz;
	char buf[BUFSIZ];

	fo = open(to, O_WRONLY | O_CREAT | O_EXCL, 0744);
	if (fo < 0 && errno == EEXIST)
		return (0);
	if (fo < 0) {
		fprintf(stderr, "While creating copy of vmod %s:\n\t%s: %s\n",
		    nm, to, VAS_errtxt(errno));
		return (1);
	}
	fi = open(fm, O_RDONLY);
	if (fi < 0) {
		fprintf(stderr, "Opening vmod %s from %s: %s\n",
		    nm, fm, VAS_errtxt(errno));
		AZ(unlink(to));
		closefd(&fo);
		return (1);
	}
	while (1) {
		sz = read(fi, buf, sizeof buf);
		if (sz == 0)
			break;
		if (sz < 0 || sz != write(fo, buf, sz)) {
			fprintf(stderr, "Copying vmod %s: %s\n",
			    nm, VAS_errtxt(errno));
			AZ(unlink(to));
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

int
mgt_vcl_symtab(struct vclprog *vp, const char *input, struct vsb *err)
{
	struct vjsn *vj;
	struct vjsn_val *v1, *v2;
	const char *typ, *perr;

	CHECK_OBJ_NOTNULL(vp, VCLPROG_MAGIC);
	AN(input);
	AN(err);
	vj = vjsn_parse(input, &perr);
	if (perr != NULL) {
		VSB_printf(err, "Invalid symbol table: parse error: %s\n",
		    perr);
		return (-1);
	}
	AN(vj);
	vp->symtab = vj;
	if (mgt_vcl_symtab_check(vp, vj, err))
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
