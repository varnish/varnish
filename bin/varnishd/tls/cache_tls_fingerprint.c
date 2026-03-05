/*-
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
 * TLS client fingerprinting (JA3/JA4)
 */

#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "vsha256.h"

#include "cache/cache_varnishd.h"
#include "cache_tls.h"
#include "vend.h"
#include "vsb.h"

#include "cache_tls_fingerprint.h"

#define IS_ASCII_ALNUM(c) \
	(((c) >= '0' && (c) <= '9') || \
	 ((c) >= 'A' && (c) <= 'Z') || \
	 ((c) >= 'a' && (c) <= 'z'))

/*
 * Raw Client Hello parse result for JA3/JA4.  Extension list is wire-accurate
 * (includes extensions OpenSSL does not expose).  All payload arrays are
 * embedded; a single malloc/free of the struct suffices.
 */
#define JA3_JA4_RAW_MAX_EXTS		64
#define JA3_JA4_RAW_MAX_CIPHERS	128
#define JA3_JA4_RAW_MAX_SIG_ALGS	64
#define JA3_JA4_RAW_MAX_ALPN		64

struct ja3_ja4_raw_ch {
	uint16_t	legacy_version;
	int		has_sni;
	unsigned char	ciphers[JA3_JA4_RAW_MAX_CIPHERS * 2];
	size_t		cipher_len;
	uint16_t	ext_types[JA3_JA4_RAW_MAX_EXTS];
	size_t		ext_count;
	unsigned char	sig_algs[JA3_JA4_RAW_MAX_SIG_ALGS * 2 + 2];
	size_t		sig_algs_len;
	unsigned char	supported_versions[32];
	size_t		supported_versions_len;
	unsigned char	alpn[JA3_JA4_RAW_MAX_ALPN];
	size_t		alpn_len;
	unsigned char	supported_groups[512];
	size_t		supported_groups_len;
	unsigned char	ec_point_formats[256];
	size_t		ec_point_formats_len;
};

/* TLS wire constants. */
#ifndef SSL3_MT_CLIENT_HELLO
#define SSL3_MT_CLIENT_HELLO			1
#endif

/* TLS extension types (IANA registry values). */
#ifndef TLSEXT_TYPE_server_name
#define TLSEXT_TYPE_server_name			0
#endif
#ifndef TLSEXT_TYPE_supported_groups
#define TLSEXT_TYPE_supported_groups		10
#endif
#ifndef TLSEXT_TYPE_ec_point_formats
#define TLSEXT_TYPE_ec_point_formats		11
#endif
#ifndef TLSEXT_TYPE_signature_algorithms
#define TLSEXT_TYPE_signature_algorithms	13
#endif
#ifndef TLSEXT_TYPE_alpn
#define TLSEXT_TYPE_alpn			16
#endif
#ifndef TLSEXT_TYPE_supported_versions
#define TLSEXT_TYPE_supported_versions		43
#endif

static int
vtls_ja3_ja4_raw_parse_clienthello(const unsigned char *buf, size_t len,
    struct ja3_ja4_raw_ch *out)
{
	size_t off, body_len, cslen, ext_len, ext_end;

	AN(buf);
	AN(out);
	memset(out, 0, sizeof(*out));

	/* type(1) + body_len(3) */
	if (len < 4 || len > VTLS_CLIENT_HELLO_MAX_LEN ||
	    buf[0] != SSL3_MT_CLIENT_HELLO)
		return (-1);
	body_len = (size_t)buf[1] << 16 | (size_t)buf[2] << 8 | buf[3];
	if (body_len > VTLS_CLIENT_HELLO_MAX_LEN - 4 ||
	    len < 4 + body_len ||
	    body_len < 2 + 32 + 1)		/* version + random + sid_len */
		return (-1);

	off = 4;
	out->legacy_version = vbe16dec(buf + off);
	off += 2 + 32;				/* skip version + random */

	/* session_id: length(1) + data */
	if (off >= len)
		return (-1);
	off += 1 + (size_t)buf[off];

	/* cipher_suites: length(2) + data */
	if (off + 2 > len)
		return (-1);
	cslen = vbe16dec(buf + off);
	off += 2;
	if (cslen > sizeof(out->ciphers) || off + cslen > len)
		return (-1);
	memcpy(out->ciphers, buf + off, cslen);
	out->cipher_len = cslen;
	off += cslen;

	/* compression_methods: length(1) + data */
	if (off >= len)
		return (-1);
	off += 1 + (size_t)buf[off];

	/* extensions: length(2) + data */
	if (off + 2 > len)
		return (-1);
	ext_len = vbe16dec(buf + off);
	off += 2;
	ext_end = off + ext_len;
	if (ext_end > len)
		return (-1);

	while (off + 4 <= ext_end) {
		uint16_t etype = vbe16dec(buf + off);
		uint16_t elen = vbe16dec(buf + off + 2);
		off += 4;
		if (off + elen > ext_end)
			break;
		if (out->ext_count < JA3_JA4_RAW_MAX_EXTS)
			out->ext_types[out->ext_count++] = etype;
		if (etype == TLSEXT_TYPE_server_name)
			out->has_sni = 1;
		else if (etype == TLSEXT_TYPE_supported_groups &&
		    elen <= sizeof(out->supported_groups)) {
			memcpy(out->supported_groups, buf + off, elen);
			out->supported_groups_len = elen;
		} else if (etype == TLSEXT_TYPE_ec_point_formats &&
		    elen <= sizeof(out->ec_point_formats)) {
			memcpy(out->ec_point_formats, buf + off, elen);
			out->ec_point_formats_len = elen;
		} else if (etype == TLSEXT_TYPE_signature_algorithms &&
		    elen >= 2 && elen <= sizeof(out->sig_algs)) {
			memcpy(out->sig_algs, buf + off, elen);
			out->sig_algs_len = elen;
		} else if (etype == TLSEXT_TYPE_alpn &&
		    elen >= 2 && elen <= sizeof(out->alpn)) {
			memcpy(out->alpn, buf + off, elen);
			out->alpn_len = elen;
		} else if (etype == TLSEXT_TYPE_supported_versions &&
		    elen >= 2 && elen <= sizeof(out->supported_versions)) {
			memcpy(out->supported_versions, buf + off, elen);
			out->supported_versions_len = elen;
		}
		off += elen;
	}
	return (0);
}

static void
vtls_ja3_parsefields(int bytes_per_field, const unsigned char *data, size_t len,
    struct vsb *ja3)
{
	size_t cnt;
	uint16_t tmp;
	int first = 1;

	AN(ja3);
	if (data == NULL)
		return;
	for (cnt = 0; cnt < len; cnt += bytes_per_field) {
		if (bytes_per_field == 1)
			tmp = *data;
		else
			tmp = vbe16dec(data);

		data += bytes_per_field;

		if (bytes_per_field != 2 || !IS_GREASE_TLS(tmp)) {
			if (!first)
				VSB_putc(ja3, '-');

			first = 0;
			VSB_printf(ja3, "%i", tmp);
		}
	}
}

int
VTLS_fingerprint_get_ja3(struct sess *sp, struct vtls_sess *tsp)
{
	const struct ja3_ja4_raw_ch *raw;
	struct vsb ja3[1];
	size_t i;
	int first, type;
	char *ja3_str;
	uintptr_t sn;

	AN(sp);
	AN(tsp);
	if (tsp->ja3_ja4_raw == NULL)
		return (0);
	raw = tsp->ja3_ja4_raw;
	AN(raw);

	sn = WS_Snapshot(sp->ws);
	WS_VSB_new(ja3, sp->ws);
	VSB_printf(ja3, "%i,", (int)raw->legacy_version);

	if (raw->cipher_len > 0)
		vtls_ja3_parsefields(2, raw->ciphers, raw->cipher_len, ja3);
	VSB_putc(ja3, ',');

	first = 1;
	for (i = 0; i < raw->ext_count; i++) {
		type = raw->ext_types[i];
		if (!IS_GREASE_TLS(type)) {
			if (!first)
				VSB_putc(ja3, '-');
			first = 0;
			VSB_printf(ja3, "%i", type);
		}
	}
	VSB_putc(ja3, ',');

	if (raw->supported_groups_len >= 2) {
		vtls_ja3_parsefields(2, raw->supported_groups + 2,
		    raw->supported_groups_len - 2, ja3);
	}
	VSB_putc(ja3, ',');

	if (raw->ec_point_formats_len >= 1) {
		vtls_ja3_parsefields(1, raw->ec_point_formats + 1,
		    raw->ec_point_formats_len - 1, ja3);
	}

	ja3_str = WS_VSB_finish(ja3, sp->ws, NULL);
	if (ja3_str == NULL) {
		VTLS_LOG(tsp->log, SLT_Error,
		    "Out of workspace_session during JA3 handling");
		WS_Reset(sp->ws, sn);
		return (1);
	}
	REPLACE(tsp->ja3, ja3_str);
	WS_Reset(sp->ws, sn);
	return (0);
}

/*
 * JA4 TLS client fingerprint.
 * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 *
 * Varnish only does TLS over TCP (protocol always "t"), SSL3 to TLS1.3.
 * All temps live on the stack; session workspace is not touched.
 * Hashed variants use incremental SHA256 and never build intermediate
 * strings.  Raw variants format directly into a stack buffer.
 * Final result is heap-copied via REPLACE.
 */
#define JA4_HASH_LEN	12
#define JA4_HASH_BUF	13
#define JA4_COUNT_CAP	99
#define JA4_CAP(x)	((x) > JA4_COUNT_CAP ? JA4_COUNT_CAP : (unsigned)(x))

static int
cmp_uint16(const void *a, const void *b)
{
	uint16_t x = *(const uint16_t *)a;
	uint16_t y = *(const uint16_t *)b;

	return ((x > y) - (x < y));
}

/*
 * SHA-256 of up to two comma-separated lowercase-hex uint16 lists
 * joined by underscore.  Truncated to 12 hex chars.
 * Both empty -> "000000000000".
 */
static void
ja4_hash_hex(const uint16_t *a, unsigned na,
    const uint16_t *b, unsigned nb, char out[JA4_HASH_BUF])
{
	VSHA256_CTX ctx;
	unsigned char digest[VSHA256_LEN];
	char hex[5];
	unsigned i, u;

	if (na == 0 && nb == 0) {
		memcpy(out, "000000000000", JA4_HASH_BUF);
		return;
	}
	VSHA256_Init(&ctx);
	for (i = 0; i < na; i++) {
		if (i > 0)
			VSHA256_Update(&ctx, ",", 1);
		snprintf(hex, sizeof(hex), "%04x", a[i]);
		VSHA256_Update(&ctx, hex, 4);
	}
	if (nb > 0) {
		if (na > 0)
			VSHA256_Update(&ctx, "_", 1);
		for (i = 0; i < nb; i++) {
			if (i > 0)
				VSHA256_Update(&ctx, ",", 1);
			snprintf(hex, sizeof(hex), "%04x", b[i]);
			VSHA256_Update(&ctx, hex, 4);
		}
	}
	VSHA256_Final(digest, &ctx);
	for (u = 0; u < JA4_HASH_LEN / 2; u++)
		sprintf(out + u * 2, "%02x", digest[u]);
	out[JA4_HASH_LEN] = '\0';
}

/*
 * Build one JA4 variant and store via REPLACE (heap copy).
 * variant is a bitfield: VTLS_JA4_SORTED and/or VTLS_JA4_HASHED.
 * Sorted variants exclude SNI/ALPN from extensions; original-order
 * variants keep them.  Session workspace is not consumed.
 */
int
VTLS_fingerprint_get_ja4_variant(struct sess *sp, struct vtls_sess *tsp,
    unsigned variant)
{
	const struct ja3_ja4_raw_ch *raw;
	int do_sort, do_hash;
	char **slot;
	uint16_t wire;
	const char *ver;
	unsigned nciphers, ext_total, nexts, nsigs;
	char alpn_first, alpn_last, part_a[16];
	uint16_t ciphers[JA3_JA4_RAW_MAX_CIPHERS];
	uint16_t exts[JA3_JA4_RAW_MAX_EXTS];
	uint16_t sigs[JA3_JA4_RAW_MAX_SIG_ALGS];
	size_t i;

	(void)sp;
	AN(tsp);
	if (tsp->ja3_ja4_raw == NULL)
		return (0);
	switch (variant) {
	case VTLS_JA4_MAIN: slot = &tsp->ja4; break;
	case VTLS_JA4_R:    slot = &tsp->ja4_r; break;
	case VTLS_JA4_O:    slot = &tsp->ja4_o; break;
	case VTLS_JA4_RO:   slot = &tsp->ja4_ro; break;
	default: return (-1);
	}
	if (*slot != NULL)
		return (0);

	raw = tsp->ja3_ja4_raw;
	AN(raw);
	do_sort = (variant & VTLS_JA4_SORTED) != 0;
	do_hash = (variant & VTLS_JA4_HASHED) != 0;

	/* --- Part A: t(ver)(sni)(nc)(ne)(alpn) --- */

	wire = raw->legacy_version;
	if (raw->supported_versions_len >= 2) {
		const unsigned char *sv = raw->supported_versions;
		uint16_t vmax = 0;
		size_t off;

		off = (raw->supported_versions_len >= 3 &&
		    (size_t)sv[0] == raw->supported_versions_len - 1)
		    ? 1 : 0;
		for (; off + 2 <= raw->supported_versions_len; off += 2) {
			uint16_t v = vbe16dec(sv + off);
			if (!IS_GREASE_TLS(v) && v > vmax)
				vmax = v;
		}
		if (vmax != 0)
			wire = vmax;
	}

	switch (wire) {
	case 0x0304: ver = "13"; break;
	case 0x0303: ver = "12"; break;
	case 0x0302: ver = "11"; break;
	case 0x0301: ver = "10"; break;
	case 0x0300: ver = "s3"; break;
	default:     ver = "00"; break;
	}

	nciphers = 0;
	for (i = 0; i + 2 <= raw->cipher_len; i += 2) {
		uint16_t c = vbe16dec(raw->ciphers + i);
		if (!IS_GREASE_TLS(c) && nciphers < JA3_JA4_RAW_MAX_CIPHERS)
			ciphers[nciphers++] = c;
	}

	ext_total = nexts = 0;
	for (i = 0; i < raw->ext_count; i++) {
		uint16_t et = raw->ext_types[i];
		if (IS_GREASE_TLS(et))
			continue;
		ext_total++;
		if (do_sort &&
		    (et == TLSEXT_TYPE_server_name || et == TLSEXT_TYPE_alpn))
			continue;
		if (nexts < JA3_JA4_RAW_MAX_EXTS)
			exts[nexts++] = et;
	}

	/* ALPN: first and last char of first protocol value.
	 * Wire: 2-byte list len, 1-byte proto len, proto bytes. */
	alpn_first = '0';
	alpn_last = '0';
	if (raw->alpn_len >= 3) {
		unsigned plen = raw->alpn[2];
		const unsigned char *p = raw->alpn + 3;
		size_t ll = vbe16dec(raw->alpn);

		if (plen > 0 && ll > 0 && plen <= ll - 1 &&
		    3 + plen <= raw->alpn_len) {
			if (IS_ASCII_ALNUM(p[0]) && IS_ASCII_ALNUM(p[plen - 1])) {
				alpn_first = (char)p[0];
				alpn_last = (char)p[plen - 1];
			} else {
				char hx[3];
				snprintf(hx, sizeof(hx), "%02x", p[0]);
				alpn_first = hx[0];
				snprintf(hx, sizeof(hx), "%02x",
				    p[plen - 1]);
				alpn_last = hx[1];
			}
		}
	}

	snprintf(part_a, sizeof(part_a), "t%s%c%02u%02u%c%c",
	    ver, raw->has_sni ? 'd' : 'i',
	    JA4_CAP(nciphers), JA4_CAP(ext_total), alpn_first, alpn_last);

	if (do_sort) {
		if (nciphers > 1)
			qsort(ciphers, nciphers, sizeof(uint16_t), cmp_uint16);
		if (nexts > 1)
			qsort(exts, nexts, sizeof(uint16_t), cmp_uint16);
	}

	/* Signature algorithms (wire order, never sorted) */
	nsigs = 0;
	if (raw->sig_algs_len >= 2) {
		uint16_t salen = vbe16dec(raw->sig_algs);
		for (i = 2; i + 2 <= 2 + (size_t)salen &&
		    i + 2 <= raw->sig_algs_len; i += 2) {
			uint16_t sa = vbe16dec(raw->sig_algs + i);
			if (!IS_GREASE_TLS(sa) &&
			    nsigs < JA3_JA4_RAW_MAX_SIG_ALGS)
				sigs[nsigs++] = sa;
		}
	}

	/* --- Assemble result --- */
	if (do_hash) {
		char ch[JA4_HASH_BUF], eh[JA4_HASH_BUF];
		char result[48];

		ja4_hash_hex(ciphers, nciphers, NULL, 0, ch);
		ja4_hash_hex(exts, nexts, sigs, nsigs, eh);
		snprintf(result, sizeof(result), "%s_%s_%s",
		    part_a, ch, eh);
		REPLACE(*slot, result);
	} else {
		char buf[2048];
		size_t off;

		off = (size_t)snprintf(buf, sizeof(buf), "%s_", part_a);
		for (i = 0; i < nciphers && off + 5 < sizeof(buf); i++)
			off += (size_t)snprintf(buf + off,
			    sizeof(buf) - off, "%s%04x",
			    i > 0 ? "," : "", ciphers[i]);
		off += (size_t)snprintf(buf + off,
		    sizeof(buf) - off, "_");
		for (i = 0; i < nexts && off + 5 < sizeof(buf); i++)
			off += (size_t)snprintf(buf + off,
			    sizeof(buf) - off, "%s%04x",
			    i > 0 ? "," : "", exts[i]);
		if (nsigs > 0) {
			off += (size_t)snprintf(buf + off,
			    sizeof(buf) - off, "_");
			for (i = 0; i < nsigs && off + 5 < sizeof(buf); i++)
				off += (size_t)snprintf(buf + off,
				    sizeof(buf) - off, "%s%04x",
				    i > 0 ? "," : "", sigs[i]);
		}
		REPLACE(*slot, buf);
	}

	return (0);
}

void
VTLS_fingerprint_raw_free(void **praw)
{
	AN(praw);
	free(*praw);
	*praw = NULL;
}

int
VTLS_fingerprint_parse_clienthello(const unsigned char *buf, size_t len,
    void **out_raw)
{
	struct ja3_ja4_raw_ch *raw;

	AN(out_raw);
	if (buf == NULL)
		return (-1);
	*out_raw = NULL;
	raw = malloc(sizeof(*raw));
	if (raw == NULL)
		return (-1);
	if (vtls_ja3_ja4_raw_parse_clienthello(buf, len, raw) != 0) {
		free(raw);
		return (-1);
	}
	*out_raw = raw;
	return (0);
}
