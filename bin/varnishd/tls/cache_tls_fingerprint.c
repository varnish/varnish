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

#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include "cache/cache_varnishd.h"
#include "cache_tls.h"
#include "vend.h"
#include "vsb.h"

#include "cache_tls_fingerprint.h"

/*
 * Raw Client Hello parse result for JA3/JA4. Extension list is wire-accurate
 * (all extensions, including those OpenSSL does not recognize). All pointer
 * fields are malloc'd; caller must vtls_ja3_ja4_raw_free().
 *
 * Limits below are sanity bounds for parsing (not from TLS spec). Real clients
 * typically send ~15-30 extensions, ~15-40 ciphers, and small ALPN/sig_algs.
 * MAX_ALPN is enough for typical protocol lists (Varnish supports up to h2).
 */
#define JA3_JA4_RAW_MAX_EXTS	64
#define JA3_JA4_RAW_MAX_CIPHERS	128
#define JA3_JA4_RAW_MAX_SIG_ALGS	64
#define JA3_JA4_RAW_MAX_ALPN	64

/* Client Hello wire layout (after TLS record header). */
#define CH_RECORD_HEADER_LEN		4
#define CH_LEGACY_VERSION_LEN		2
#define CH_RANDOM_LEN			32
#define CH_SESSION_ID_LENGTH_LEN		1
#define CH_MIN_BODY_LEN			(CH_LEGACY_VERSION_LEN + CH_RANDOM_LEN + CH_SESSION_ID_LENGTH_LEN)
#define CH_CIPHER_SUITES_LEN_LEN		2
#define CH_COMPRESSION_LEN_LEN		1
#define CH_EXTENSIONS_LEN_LEN		2

struct ja3_ja4_raw_ch {
	uint16_t		legacy_version;
	unsigned char		*ciphers;
	size_t			cipher_len;
	int			*ext_types;
	size_t			ext_count;
	unsigned char		*sig_algs;
	size_t			sig_algs_len;
	unsigned char		*supported_versions;
	size_t			supported_versions_len;
	int			has_sni;
	unsigned char		*alpn;
	size_t			alpn_len;
	unsigned char		*supported_groups;
	size_t			supported_groups_len;
	unsigned char		*ec_point_formats;
	size_t			ec_point_formats_len;
};

/* TLS extension types (wire values); use in raw Client Hello parser. */
#ifndef TLSEXT_TYPE_server_name
#define TLSEXT_TYPE_server_name			0
#endif
#ifndef TLSEXT_TYPE_alpn
#define TLSEXT_TYPE_alpn			16
#endif

/* Table-driven extension payload capture (SNI handled separately). */
enum {
	EXT_SUPPORTED_GROUPS,
	EXT_EC_POINT_FORMATS,
	EXT_SIG_ALGS,
	EXT_ALPN,
	EXT_SUPPORTED_VERSIONS
};
static const struct {
	uint16_t	etype;
	size_t	min_len;
	size_t	max_len;
	int	field;
} ja4_ext_table[] = {
	{ 10, 1, 512, EXT_SUPPORTED_GROUPS },
	{ 11, 1, 256, EXT_EC_POINT_FORMATS },
	{ 13, 2, JA3_JA4_RAW_MAX_SIG_ALGS * 2 + 2, EXT_SIG_ALGS },
	{ TLSEXT_TYPE_alpn, 2, JA3_JA4_RAW_MAX_ALPN, EXT_ALPN },
	{ 43, 2, 32, EXT_SUPPORTED_VERSIONS },
};

static int
set_raw_ext_payload(unsigned char **out, size_t *out_len,
    const unsigned char *src, size_t len)
{
	unsigned char *copy;

	AN(out);
	AN(out_len);
	if (len > 0 && src == NULL)
		return (-1);
	copy = malloc(len);
	if (copy == NULL)
		return (-1);
	memcpy(copy, src, len);
	free(*out);
	*out = copy;
	*out_len = len;
	return (0);
}

static void
vtls_ja3_ja4_raw_free(struct ja3_ja4_raw_ch *raw)
{
	AN(raw);
	free(raw->ciphers);
	free(raw->ext_types);
	free(raw->sig_algs);
	free(raw->supported_versions);
	free(raw->alpn);
	free(raw->supported_groups);
	free(raw->ec_point_formats);
	memset(raw, 0, sizeof(*raw));
}

static int
vtls_ja3_ja4_raw_parse_clienthello(const unsigned char *buf, size_t len,
    struct ja3_ja4_raw_ch *out)
{
	size_t off, body_len, ext_len, ext_end;
	uint16_t cipher_suites_len;
	unsigned char *copy;

	AN(buf);
	AN(out);
	memset(out, 0, sizeof(*out));
	if (len < CH_RECORD_HEADER_LEN || len > VTLS_CLIENT_HELLO_MAX_LEN ||
	    buf[0] != SSL3_MT_CLIENT_HELLO)
		return (-1);
	/* TLS record payload length (3 bytes big-endian) */
	body_len = (size_t)buf[1] << 16 | (size_t)buf[2] << 8 | buf[3];
	if (body_len > VTLS_CLIENT_HELLO_MAX_LEN - CH_RECORD_HEADER_LEN ||
	    len < CH_RECORD_HEADER_LEN + body_len || body_len < CH_MIN_BODY_LEN)
		return (-1);
	off = CH_RECORD_HEADER_LEN;
	out->legacy_version = vbe16dec(buf + off);
	off += CH_LEGACY_VERSION_LEN + CH_RANDOM_LEN;
	if (off + CH_SESSION_ID_LENGTH_LEN > len)
		return (-1);
	off += CH_SESSION_ID_LENGTH_LEN + (size_t)buf[off];
	if (off + CH_CIPHER_SUITES_LEN_LEN > len)
		return (-1);
	cipher_suites_len = vbe16dec(buf + off);
	off += CH_CIPHER_SUITES_LEN_LEN;
	if (cipher_suites_len > JA3_JA4_RAW_MAX_CIPHERS * 2)
		return (-1);
	copy = malloc(cipher_suites_len);
	if (copy == NULL)
		return (-1);
	memcpy(copy, buf + off, cipher_suites_len);
	out->ciphers = copy;
	out->cipher_len = cipher_suites_len;
	off += cipher_suites_len;
	if (off + CH_COMPRESSION_LEN_LEN > len)
		goto fail;
	off += CH_COMPRESSION_LEN_LEN + (size_t)buf[off];
	if (off + CH_EXTENSIONS_LEN_LEN > len)
		goto fail;
	ext_len = vbe16dec(buf + off);
	off += CH_EXTENSIONS_LEN_LEN;
	ext_end = off + ext_len;
	if (ext_end > len)
		goto fail;

	out->ext_types = malloc(JA3_JA4_RAW_MAX_EXTS * sizeof(int));
	if (out->ext_types == NULL)
		goto fail;

	while (off + 4 <= ext_end && out->ext_count < JA3_JA4_RAW_MAX_EXTS) {
		uint16_t etype = vbe16dec(buf + off);
		uint16_t elen = vbe16dec(buf + off + 2);
		size_t t;
		off += 4;
		if (off + elen > ext_end)
			break;
		out->ext_types[out->ext_count++] = (int)etype;
		if (etype == TLSEXT_TYPE_server_name)
			out->has_sni = 1;
		else {
			for (t = 0; t < sizeof(ja4_ext_table) / sizeof(ja4_ext_table[0]); t++) {
				if (ja4_ext_table[t].etype == etype &&
				    elen >= ja4_ext_table[t].min_len &&
				    elen <= ja4_ext_table[t].max_len) {
					switch (ja4_ext_table[t].field) {
					case EXT_SUPPORTED_GROUPS:
						(void)set_raw_ext_payload(&out->supported_groups,
						    &out->supported_groups_len, buf + off, elen);
						break;
					case EXT_EC_POINT_FORMATS:
						(void)set_raw_ext_payload(&out->ec_point_formats,
						    &out->ec_point_formats_len, buf + off, elen);
						break;
					case EXT_SIG_ALGS:
						(void)set_raw_ext_payload(&out->sig_algs,
						    &out->sig_algs_len, buf + off, elen);
						break;
					case EXT_ALPN:
						(void)set_raw_ext_payload(&out->alpn,
						    &out->alpn_len, buf + off, elen);
						break;
					case EXT_SUPPORTED_VERSIONS:
						(void)set_raw_ext_payload(&out->supported_versions,
						    &out->supported_versions_len, buf + off, elen);
						break;
					}
					break;
				}
			}
		}
		off += elen;
	}
	return (0);
fail:
	vtls_ja3_ja4_raw_free(out);
	return (-1);
}

static void
vtls_ja3_parsefields(int bytes_per_field, const unsigned char *data, int len,
    struct vsb *ja3)
{
	int cnt;
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
VTLS_fingerprint_get_ja3(SSL *ssl, struct sess *sp, struct vtls_sess *tsp)
{
	const struct ja3_ja4_raw_ch *raw;
	struct vsb ja3[1];
	size_t i;
	int first, type;
	char *ja3_str;
	uintptr_t sn;

	(void)ssl;
	AN(sp);
	AN(tsp);
	if (tsp->ja3_ja4_raw == NULL)
		return (0);
	raw = tsp->ja3_ja4_raw;
	AN(raw);

	sn = WS_Snapshot(sp->ws);
	WS_VSB_new(ja3, sp->ws);
	VSB_printf(ja3, "%i,", (int)raw->legacy_version);

	if (raw->ciphers != NULL && raw->cipher_len > 0)
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

	if (raw->supported_groups != NULL && raw->supported_groups_len >= 2) {
		vtls_ja3_parsefields(2, raw->supported_groups + 2,
		    raw->supported_groups_len - 2, ja3);
	}
	VSB_putc(ja3, ',');

	if (raw->ec_point_formats != NULL && raw->ec_point_formats_len >= 1) {
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
 * JA4 client fingerprint. Spec: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 *
 * Format: (protocol)(tls_ver)(sni)(nr_ciphers:02)(nr_exts:02)(alpn_first)(alpn_last)_(cipher_hash)_(ext_sig_hash)
 *
 * First chunk:
 *   protocol: "t" TLS over TCP, "q" QUIC, "d" DTLS
 *   tls_ver:  2 chars; if supported_versions exists, max non-GREASE; else Protocol Version
 *   sni:      "d" if SNI present, "i" otherwise
 *   nr_ciphers/nr_exts: count non-GREASE; cap at 99. Extensions count includes SNI and ALPN.
 *   alpn:     first and last ASCII alphanumeric of first ALPN value; else hex; "00" if none
 *
 * Cipher hash: first 12 hex chars (lowercase) of SHA256 of sorted 4-char hex ciphers, comma-sep, non-GREASE. Empty -> "000000000000".
 *
 * Extension hash: first 12 hex chars of SHA256 of (sorted extension hex, excluding SNI and ALPN)_(sig algs in order). No sig algs -> no underscore. Empty -> "000000000000".
 */
#define JA4_HASH_LEN		12	/* hex chars in Part B/C hashes */
#define JA4_HASH_BUF		13	/* JA4_HASH_LEN + NUL */
#define JA4_COUNT_CAP		99	/* cap for cipher/extension counts */
#define JA4_CAP(x)		((x) > JA4_COUNT_CAP ? JA4_COUNT_CAP : (unsigned)(x))
#define JA4_PART_A_MAX		16	/* max length of Part A string */
#define JA4_RESULT_MAX		(JA4_PART_A_MAX + 1 + JA4_HASH_LEN + 1 + JA4_HASH_LEN + 1)
#define JA4_RAW_RESULT_MAX	2048	/* max length of raw JA4 (Part A + ciphers + exts + sig_algs) */
#define JA4_HEX_ITEM_MAX	5	/* max chars per comma-sep hex item (e.g. "abcd,") */

/* ALPN wire layout: 2-byte list length, then for each protocol 1-byte length + payload. */
#define ALPN_LIST_LEN_OFFSET		0
#define ALPN_FIRST_PROTO_LEN_OFFSET	2
#define ALPN_FIRST_PROTO_OFFSET		3

static inline size_t
strlen_safe(const char *s)
{
	return (s != NULL && *s != '\0') ? strlen(s) : 0;
}

static void
vtls_ja4_hash12(const char *in, size_t len, char out[JA4_HASH_BUF])
{
	unsigned char digest[SHA256_DIGEST_LENGTH];
	unsigned u;

	if (len == 0) {
		memcpy(out, "000000000000", JA4_HASH_BUF);
		return;
	}
	SHA256((const unsigned char *)in, len, digest);
	for (u = 0; u < JA4_HASH_LEN / 2; u++)
		sprintf(out + u * 2, "%02x", digest[u]);
	out[JA4_HASH_LEN] = '\0';
}

#define CMP_QSORT(type) \
static int \
cmp_##type(const void *a, const void *b) \
{ \
	type x = *(const type *)a, y = *(const type *)b; \
	return (x < y ? -1 : (x > y ? 1 : 0)); \
}
CMP_QSORT(uint16_t)
CMP_QSORT(int)

/* Format array as comma-sep hex. kind: 0 = uint16 %04x, 1 = int %04x, 2 = uint16 %02x%02x (sig_algs). */
static char *
ja4_fmt_hex_list(struct ws *ws, int kind, const void *arr, size_t n)
{
	size_t buf_len, off, i;
	char *buf;
	const uint16_t *u16 = arr;
	const int *i32 = arr;

	AN(ws);
	if (n == 0 || (n > 0 && arr == NULL))
		return (NULL);
	buf_len = n * JA4_HEX_ITEM_MAX;
	buf = WS_Alloc(ws, buf_len);
	if (buf == NULL)
		return (NULL);
	off = 0;
	for (i = 0; i < n; i++) {
		const char *sep = i > 0 ? "," : "";
		switch (kind) {
		case 0:
			off += (size_t)snprintf(buf + off, buf_len - off, "%s%04x", sep, u16[i]);
			break;
		case 1:
			off += (size_t)snprintf(buf + off, buf_len - off, "%s%04x", sep, i32[i]);
			break;
		default:
			off += (size_t)snprintf(buf + off, buf_len - off, "%s%02x%02x", sep,
			    (u16[i] >> 8) & 0xff, u16[i] & 0xff);
			break;
		}
	}
	return (buf);
}

/* TLS/DTLS wire version values (for JA4 Part A). */
#define TLS1_3_WIRE	0x0304
#define TLS1_2_WIRE	0x0303
#define TLS1_1_WIRE	0x0302
#define TLS1_0_WIRE	0x0301
#define SSL3_WIRE	0x0300
#define SSL2_WIRE	0x0002
#define DTLS1_0_WIRE	0xfeff
#define DTLS1_2_WIRE	0xfefd
#define DTLS1_3_WIRE	0xfefc

/*
 * Build one JA4 variant from the parsed Client Hello and store it in tsp.
 * variant is a bitfield: VTLS_JA4_SORTED and/or VTLS_JA4_HASHED (use
 * VTLS_JA4_MAIN/R/O/RO for the four slots). Returns 0 on success.
 */
int
VTLS_fingerprint_get_ja4_variant(struct sess *sp, struct vtls_sess *tsp,
    unsigned variant)
{
	const struct ja3_ja4_raw_ch *raw;
	struct ws *ws;
	uintptr_t sn;

	/* Part A: version, SNI, counts, ALPN */
	uint16_t wire, vmax;
	const unsigned char *sv;
	const char *ver_str;
	size_t n_ciphers, n_exts, n_exts_a;
	char alpn_first, alpn_last;
	const unsigned char *alpn_data, *proto;
	size_t list_len, proto_len, i;
	char hex_buf[512];

	/* Variant and Part B/C: hex strings and hashes */
	int do_sort, do_hash;
	char *ciphers_str, *exts_str;
	char *ciphers_str_sorted, *ciphers_str_orig, *exts_str_sorted, *exts_str_orig;
	char *sig_algs_str;
	char ciphers_hash[JA4_HASH_BUF], exts_sigs_hash[JA4_HASH_BUF];

	/* Part B/C: workspace arrays and loop indices */
	uint16_t *ciphers;
	int *exts;
	char *exts_str_ro;
	uint16_t *sigs;
	size_t ci, cj, ei, ej, si, sj, n_sig;

	char part_a[JA4_PART_A_MAX];
	char buf[JA4_RAW_RESULT_MAX];
	char *result;
	char **result_slot;
	const char *part_b, *part_c;
	int has_sig;

	AN(sp);
	AN(tsp);
	if (tsp->ja3_ja4_raw == NULL)
		return (-1);
	switch (variant) {
	case VTLS_JA4_MAIN: result_slot = &tsp->ja4; break;
	case VTLS_JA4_R:   result_slot = &tsp->ja4_r; break;
	case VTLS_JA4_O:   result_slot = &tsp->ja4_o; break;
	case VTLS_JA4_RO:  result_slot = &tsp->ja4_ro; break;
	default: return (-1);
	}
	if (*result_slot != NULL)
		return (0);

	raw = tsp->ja3_ja4_raw;
	AN(raw);
	ws = sp->ws;
	AN(ws);
	sn = WS_Snapshot(ws);

	/* Part A: version, SNI, counts, ALPN. */
	if (raw->supported_versions != NULL && raw->supported_versions_len >= 2) {
		size_t off;
		uint16_t v;
		sv = raw->supported_versions;
		off = (raw->supported_versions_len >= 3 &&
		    (size_t)sv[0] == raw->supported_versions_len - 1) ? 1 : 0;
		vmax = 0;
		for (; off + 2 <= raw->supported_versions_len; off += 2) {
			v = vbe16dec(sv + off);
			if (!IS_GREASE_TLS(v) && v > vmax)
				vmax = v;
		}
		wire = (vmax != 0) ? vmax : raw->legacy_version;
	} else
		wire = raw->legacy_version;

	switch (wire) {
	case TLS1_3_WIRE:  ver_str = "13"; break;
	case TLS1_2_WIRE:  ver_str = "12"; break;
	case TLS1_1_WIRE:  ver_str = "11"; break;
	case TLS1_0_WIRE:  ver_str = "10"; break;
	case SSL3_WIRE:    ver_str = "s3"; break;
	default: ver_str = "00"; break;
	}

	/* Count non-GREASE ciphers (for Part A display and Part B). */
	n_ciphers = 0;
	for (ci = 0; ci + 2 <= raw->cipher_len; ci += 2) {
		if (!IS_GREASE_TLS(vbe16dec(raw->ciphers + ci)))
			n_ciphers++;
	}
	/* Count extensions: n_exts_a = all non-GREASE (Part A), n_exts = exclude SNI/ALPN (Part C). */
	n_exts_a = 0;
	n_exts = 0;
	for (ei = 0; ei < raw->ext_count; ei++) {
		int et = raw->ext_types[ei];
		if (IS_GREASE_TLS(et))
			continue;
		n_exts_a++;
		if (et != TLSEXT_TYPE_server_name && et != TLSEXT_TYPE_alpn)
			n_exts++;
	}

	alpn_first = '0';
	alpn_last = '0';
	alpn_data = raw->alpn;
	if (alpn_data == NULL || raw->alpn_len < ALPN_FIRST_PROTO_OFFSET)
		goto alpn_done;
	list_len = vbe16dec(alpn_data + ALPN_LIST_LEN_OFFSET);
	if (list_len == 0 || list_len > raw->alpn_len - ALPN_FIRST_PROTO_LEN_OFFSET)
		goto alpn_done;
	proto_len = alpn_data[ALPN_FIRST_PROTO_LEN_OFFSET];
	if (proto_len == 0 || proto_len > list_len - 1)
		goto alpn_done;
	proto = alpn_data + ALPN_FIRST_PROTO_OFFSET;
	if (proto_len * 2 > sizeof(hex_buf))
		goto alpn_done;
	if (isalnum((unsigned char)proto[0]) &&
	    isalnum((unsigned char)proto[proto_len - 1])) {
		alpn_first = (char)proto[0];
		alpn_last = (char)proto[proto_len - 1];
	} else {
		for (i = 0; i < proto_len; i++)
			snprintf(hex_buf + 2 * i, 3, "%02x", proto[i]);
		hex_buf[proto_len * 2] = '\0';
		alpn_first = hex_buf[0];
		alpn_last = (proto_len * 2 > 1 ? hex_buf[proto_len * 2 - 1] : hex_buf[0]);
	}
alpn_done:
	sprintf(part_a, "t%s%c%02u%02u%c%c", ver_str,
	    raw->has_sni ? 'd' : 'i', JA4_CAP(n_ciphers), JA4_CAP(n_exts_a),
	    alpn_first, alpn_last);

	do_sort = (variant & VTLS_JA4_SORTED) != 0;
	do_hash = (variant & VTLS_JA4_HASHED) != 0;

	/* Part B: cipher list (non-GREASE). */
	ciphers_str_sorted = NULL;
	ciphers_str_orig = NULL;
	if (n_ciphers > 0) {
		ciphers = WS_Alloc(ws, n_ciphers * sizeof(uint16_t));
		if (ciphers == NULL)
			goto fail;
		for (ci = 0, cj = 0; ci + 2 <= raw->cipher_len; ci += 2) {
			uint16_t c = vbe16dec(raw->ciphers + ci);
			if (!IS_GREASE_TLS(c))
				ciphers[cj++] = c;
		}
		ciphers_str_orig = ja4_fmt_hex_list(ws, 0, ciphers, n_ciphers);
		if (ciphers_str_orig == NULL)
			goto fail;
		qsort(ciphers, n_ciphers, sizeof(uint16_t), cmp_uint16_t);
		ciphers_str_sorted = ja4_fmt_hex_list(ws, 0, ciphers, n_ciphers);
		if (ciphers_str_sorted == NULL)
			goto fail;
	}
	ciphers_str = do_sort ? ciphers_str_sorted : ciphers_str_orig;
	if (do_hash)
		vtls_ja4_hash12(ciphers_str ? ciphers_str : "", strlen_safe(ciphers_str), ciphers_hash);

	/* Part C: extensions (exclude SNI/ALPN). */
	exts_str_sorted = NULL;
	exts_str_orig = NULL;
	if (n_exts > 0) {
		exts = WS_Alloc(ws, n_exts * sizeof(int));
		if (exts == NULL)
			goto fail;
		for (ei = 0, ej = 0; ei < raw->ext_count; ei++) {
			int et = raw->ext_types[ei];
			if (!IS_GREASE_TLS(et) && et != TLSEXT_TYPE_server_name && et != TLSEXT_TYPE_alpn)
				exts[ej++] = et;
		}
		exts_str_orig = ja4_fmt_hex_list(ws, 1, exts, n_exts);
		if (exts_str_orig == NULL)
			goto fail;
		qsort(exts, n_exts, sizeof(int), cmp_int);
		exts_str_sorted = ja4_fmt_hex_list(ws, 1, exts, n_exts);
		if (exts_str_sorted == NULL)
			goto fail;
	}
	exts_str = do_sort ? exts_str_sorted : exts_str_orig;

	/* JA4_ro: extension list in original order including SNI and ALPN (spec). Use stack buffer to save workspace. */
	exts_str_ro = NULL;
	if (!do_hash && !do_sort && n_exts_a > 0) {
		char exts_ro_buf[JA3_JA4_RAW_MAX_EXTS * JA4_HEX_ITEM_MAX];
		size_t off = 0;

		for (ei = 0; ei < raw->ext_count && off < sizeof(exts_ro_buf) - JA4_HEX_ITEM_MAX; ei++) {
			int et = raw->ext_types[ei];
			if (IS_GREASE_TLS(et))
				continue;
			off += (size_t)snprintf(exts_ro_buf + off,
			    sizeof(exts_ro_buf) - off, "%s%04x", off > 0 ? "," : "", et);
		}
		exts_str_ro = WS_Copy(ws, exts_ro_buf, -1);
		if (exts_str_ro == NULL)
			goto fail;
	}

	/* Signature algorithms. */
	sig_algs_str = NULL;
	n_sig = 0;
	if (raw->sig_algs != NULL && raw->sig_algs_len >= 2) {
		uint16_t list_len = vbe16dec(raw->sig_algs);
		for (si = 2; si + 2 <= 2 + (size_t)list_len && si + 2 <= raw->sig_algs_len; si += 2) {
			if (!IS_GREASE_TLS(vbe16dec(raw->sig_algs + si)))
				n_sig++;
		}
		if (n_sig > 0) {
			sigs = WS_Alloc(ws, n_sig * sizeof(uint16_t));
			if (sigs == NULL)
				goto fail;
			for (si = 2, sj = 0; si + 2 <= 2 + (size_t)list_len && si + 2 <= raw->sig_algs_len; si += 2) {
				uint16_t sa = vbe16dec(raw->sig_algs + si);
				if (!IS_GREASE_TLS(sa))
					sigs[sj++] = sa;
			}
			sig_algs_str = ja4_fmt_hex_list(ws, 2, sigs, n_sig);
			if (sig_algs_str == NULL)
				goto fail;
		}
	}
	has_sig = (strlen_safe(sig_algs_str) > 0);

	/* exts_sigs_hash when do_hash (uses WS_Alloc for combined). */
	if (do_hash) {
		size_t exts_len, sig_len, total;
		char *combined;

		exts_len = strlen_safe(exts_str);
		sig_len = strlen_safe(sig_algs_str);
		if (exts_len == 0 && sig_len == 0)
			vtls_ja4_hash12("", 0, exts_sigs_hash);
		else {
			total = exts_len + (sig_len > 0 ? 1 + sig_len : 0);
			combined = WS_Alloc(ws, total + 1);
			if (combined == NULL)
				goto fail;
			snprintf(combined, total + 1, "%s%s%s",
			    exts_str ? exts_str : "",
			    (exts_len > 0 && sig_len > 0) ? "_" : "",
			    sig_algs_str ? sig_algs_str : "");
			vtls_ja4_hash12(combined, total, exts_sigs_hash);
		}
	}

	/* Build result: part_a _ cipher_part _ ext_part [_ sig_algs]. */
	part_b = do_hash ? ciphers_hash : (ciphers_str ? ciphers_str : "");
	part_c = do_hash ? exts_sigs_hash : (do_sort ? (exts_str ? exts_str : "")
	    : (exts_str_ro ? exts_str_ro : ""));
	if (do_hash)
		sprintf(buf, "%s_%s_%s", part_a, part_b, part_c);
	else
		sprintf(buf, has_sig ? "%s_%s_%s_%s" : "%s_%s_%s",
		    part_a, part_b, part_c, has_sig ? sig_algs_str : "");
	result = WS_Copy(ws, buf, -1);
	if (result == NULL)
		goto fail;
	REPLACE(*result_slot, result);
	WS_Reset(ws, sn);
	return (0);
fail:
	VTLS_LOG(tsp->log, SLT_Error,
	    "Out of workspace_session during JA4 handling");
	WS_Reset(ws, sn);
	return (1);
}

void
VTLS_fingerprint_raw_free(void **praw)
{
	AN(praw);
	if (*praw == NULL)
		return;
	vtls_ja3_ja4_raw_free(*praw);
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
	raw = malloc(sizeof(struct ja3_ja4_raw_ch));
	if (raw == NULL)
		return (-1);
	if (vtls_ja3_ja4_raw_parse_clienthello(buf, len, raw) != 0) {
		free(raw);
		return (-1);
	}
	*out_raw = raw;
	return (0);
}
