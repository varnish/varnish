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
 */
#define JA3_JA4_RAW_MAX_EXTS	256
#define JA3_JA4_RAW_MAX_CIPHERS	256
#define JA3_JA4_RAW_MAX_SIG_ALGS	256
#define JA3_JA4_RAW_MAX_ALPN	256

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
set_raw_ext_payload(unsigned char **out, size_t *out_len,
    const unsigned char *src, size_t len)
{
	unsigned char *copy;

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
	if (raw == NULL)
		return;
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

	memset(out, 0, sizeof(*out));
	if (len < CH_RECORD_HEADER_LEN || buf[0] != SSL3_MT_CLIENT_HELLO)
		return (-1);
	/* TLS record payload length (3 bytes big-endian) */
	body_len = (size_t)buf[1] << 16 | (size_t)buf[2] << 8 | buf[3];
	if (len < CH_RECORD_HEADER_LEN + body_len || body_len < CH_MIN_BODY_LEN)
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
		off += 4;
		if (off + elen > ext_end)
			break;
		out->ext_types[out->ext_count++] = (int)etype;
		if (etype == TLSEXT_TYPE_server_name)
			out->has_sni = 1;
		else if (etype == TLSEXT_TYPE_supported_groups && elen > 0 && elen <= 512)
			(void)set_raw_ext_payload(&out->supported_groups,
			    &out->supported_groups_len, buf + off, elen);
		else if (etype == TLSEXT_TYPE_ec_point_formats && elen > 0 && elen <= 256)
			(void)set_raw_ext_payload(&out->ec_point_formats,
			    &out->ec_point_formats_len, buf + off, elen);
		else if (etype == TLSEXT_TYPE_signature_algorithms && elen >= 2 &&
		    elen <= JA3_JA4_RAW_MAX_SIG_ALGS * 2 + 2)
			(void)set_raw_ext_payload(&out->sig_algs, &out->sig_algs_len,
			    buf + off, elen);
		else if (etype == TLSEXT_TYPE_alpn && elen >= 2 && elen <= JA3_JA4_RAW_MAX_ALPN)
			(void)set_raw_ext_payload(&out->alpn, &out->alpn_len,
			    buf + off, elen);
		else if (etype == TLSEXT_TYPE_supported_versions && elen >= 2 && elen <= 32)
			(void)set_raw_ext_payload(&out->supported_versions,
			    &out->supported_versions_len, buf + off, elen);
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

static int
vtls_get_ja3_from_raw(const struct ja3_ja4_raw_ch *raw, struct sess *sp,
    struct vtls_sess *tsp)
{
	struct vsb ja3[1];
	size_t i;
	int first, type;
	char *ja3_str;
	uintptr_t sn;

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

static int
vtls_get_ja3(SSL *ssl, struct sess *sp, struct vtls_sess *tsp)
{
	(void)ssl;
	if (tsp->ja3_ja4_raw == NULL)
		return (0);
	return (vtls_get_ja3_from_raw(tsp->ja3_ja4_raw, sp, tsp));
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
#define JA4_PART_A_MAX		16	/* max length of Part A string */
#define JA4_RESULT_MAX		(JA4_PART_A_MAX + 1 + JA4_HASH_LEN + 1 + JA4_HASH_LEN + 1)
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

static int
cmp_uint16(const void *a, const void *b)
{
	uint16_t x = *(const uint16_t *)a, y = *(const uint16_t *)b;
	return (x < y ? -1 : (x > y ? 1 : 0));
}

static int
cmp_int(const void *a, const void *b)
{
	int x = *(const int *)a, y = *(const int *)b;
	return (x < y ? -1 : (x > y ? 1 : 0));
}

/* Format array as comma-separated hex string in workspace. */
static char *
ja4_format_hex_list_uint16(struct ws *ws, const uint16_t *arr, size_t n)
{
	size_t buf_len, off, i;
	char *buf;

	if (n == 0)
		return (NULL);
	buf_len = n * JA4_HEX_ITEM_MAX;
	buf = WS_Alloc(ws, buf_len);
	if (buf == NULL)
		return (NULL);
	off = 0;
	for (i = 0; i < n; i++)
		off += (size_t)snprintf(buf + off, buf_len - off, "%s%04x",
		    i > 0 ? "," : "", arr[i]);
	return (buf);
}

static char *
ja4_format_hex_list_int(struct ws *ws, const int *arr, size_t n)
{
	size_t buf_len, off, i;
	char *buf;

	if (n == 0)
		return (NULL);
	buf_len = n * JA4_HEX_ITEM_MAX;
	buf = WS_Alloc(ws, buf_len);
	if (buf == NULL)
		return (NULL);
	off = 0;
	for (i = 0; i < n; i++)
		off += (size_t)snprintf(buf + off, buf_len - off, "%s%04x",
		    i > 0 ? "," : "", arr[i]);
	return (buf);
}

/* Format uint16 array as comma-sep byte pairs (high byte first) for JA4 sig_algs. */
static char *
ja4_format_hex_list_sig_algs(struct ws *ws, const uint16_t *arr, size_t n)
{
	size_t buf_len, off, i;
	char *buf;

	if (n == 0)
		return (NULL);
	buf_len = n * JA4_HEX_ITEM_MAX;
	buf = WS_Alloc(ws, buf_len);
	if (buf == NULL)
		return (NULL);
	off = 0;
	for (i = 0; i < n; i++)
		off += (size_t)snprintf(buf + off, buf_len - off, "%s%02x%02x",
		    i > 0 ? "," : "", (arr[i] >> 8) & 0xff, arr[i] & 0xff);
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

static const char *
ja4_version_str(uint16_t v)
{
	switch (v) {
	case TLS1_3_WIRE:  return "13";
	case TLS1_2_WIRE:  return "12";
	case TLS1_1_WIRE:  return "11";
	case TLS1_0_WIRE:  return "10";
	case SSL3_WIRE:    return "s3";
	case SSL2_WIRE:    return "s2";
	case DTLS1_0_WIRE: return "d1";
	case DTLS1_2_WIRE: return "d2";
	case DTLS1_3_WIRE: return "d3";
	default: return "00";
	}
}

static const char *
ja4_version_str_from_raw(const struct ja3_ja4_raw_ch *raw)
{
	const unsigned char *sv;
	size_t sv_len, off, vi;
	uint16_t v, vmax;

	if (raw->supported_versions == NULL || raw->supported_versions_len < 2)
		return (ja4_version_str(raw->legacy_version));
	sv = raw->supported_versions;
	sv_len = raw->supported_versions_len;
	off = (sv_len >= 3 && (size_t)sv[0] == sv_len - 1) ? 1 : 0;
	vmax = 0;
	for (vi = off; vi + 2 <= sv_len; vi += 2) {
		v = vbe16dec(sv + vi);
		if (!IS_GREASE_TLS(v) && v > vmax)
			vmax = v;
	}
	if (vmax != 0)
		return (ja4_version_str(vmax));
	return (ja4_version_str(raw->legacy_version));
}

static void
ja4_alpn_first_last_raw(const unsigned char *alpn_data, size_t alpn_len,
    char *alpn_first, char *alpn_last)
{
	size_t list_len, proto_len;
	const unsigned char *proto;
	size_t hi;
	char hex_buf[512];

	*alpn_first = '0';
	*alpn_last = '0';
	if (alpn_data == NULL || alpn_len < ALPN_FIRST_PROTO_OFFSET)
		return;
	list_len = vbe16dec(alpn_data + ALPN_LIST_LEN_OFFSET);
	if (list_len == 0 || list_len > alpn_len - ALPN_FIRST_PROTO_LEN_OFFSET)
		return;
	proto_len = alpn_data[ALPN_FIRST_PROTO_LEN_OFFSET];
	if (proto_len == 0 || proto_len > list_len - 1)
		return;
	proto = alpn_data + ALPN_FIRST_PROTO_OFFSET;
	if (proto_len * 2 > sizeof(hex_buf))
		return;
	if (isalnum((unsigned char)proto[0]) &&
	    isalnum((unsigned char)proto[proto_len - 1])) {
		*alpn_first = (char)proto[0];
		*alpn_last = (char)proto[proto_len - 1];
		return;
	}
	for (hi = 0; hi < proto_len; hi++) {
		hex_buf[2 * hi] = "0123456789abcdef"[proto[hi] >> 4];
		hex_buf[2 * hi + 1] = "0123456789abcdef"[proto[hi] & 0xf];
	}
	hex_buf[proto_len * 2] = '\0';
	*alpn_first = hex_buf[0];
	*alpn_last = (proto_len * 2 > 1 ? hex_buf[proto_len * 2 - 1] : hex_buf[0]);
}

static int
ja4_build_cipher_list_raw(struct ws *ws, const unsigned char *cipher_list,
    size_t cipher_list_len, int sorted, char **out)
{
	size_t cipher_count, ci, cj;
	uint16_t *ciphers;

	cipher_count = 0;
	for (ci = 0; ci + 2 <= cipher_list_len; ci += 2) {
		if (!IS_GREASE_TLS(vbe16dec(cipher_list + ci)))
			cipher_count++;
	}
	*out = WS_Alloc(ws, 1);
	if (*out == NULL)
		return (-1);
	**out = '\0';
	if (cipher_count == 0)
		return (0);
	ciphers = WS_Alloc(ws, cipher_count * sizeof(uint16_t));
	if (ciphers == NULL)
		return (-1);
	for (ci = 0, cj = 0; ci + 2 <= cipher_list_len; ci += 2) {
		uint16_t c = vbe16dec(cipher_list + ci);
		if (!IS_GREASE_TLS(c))
			ciphers[cj++] = c;
	}
	if (sorted)
		qsort(ciphers, cipher_count, sizeof(uint16_t), cmp_uint16);
	*out = ja4_format_hex_list_uint16(ws, ciphers, cipher_count);
	return (*out == NULL ? -1 : 0);
}

static int
ja4_build_sig_algs_str_raw(struct ws *ws, const unsigned char *sig_alg_data,
    size_t sig_alg_len, char **out)
{
	uint16_t sig_alg_list_len;
	size_t si, n, sj;
	uint16_t *sigs;

	*out = WS_Alloc(ws, 1);
	if (*out == NULL)
		return (-1);
	**out = '\0';
	if (sig_alg_data == NULL || sig_alg_len < 2)
		return (0);
	sig_alg_list_len = vbe16dec(sig_alg_data);
	n = 0;
	for (si = 2; si + 2 <= 2 + (size_t)sig_alg_list_len && si + 2 <= sig_alg_len;
	    si += 2) {
		if (!IS_GREASE_TLS(vbe16dec(sig_alg_data + si)))
			n++;
	}
	if (n == 0)
		return (0);
	sigs = WS_Alloc(ws, n * sizeof(uint16_t));
	if (sigs == NULL)
		return (-1);
	for (si = 2, sj = 0; si + 2 <= 2 + (size_t)sig_alg_list_len && si + 2 <= sig_alg_len;
	    si += 2) {
		uint16_t sa = vbe16dec(sig_alg_data + si);
		if (!IS_GREASE_TLS(sa))
			sigs[sj++] = sa;
	}
	*out = ja4_format_hex_list_sig_algs(ws, sigs, n);
	return (*out == NULL ? -1 : 0);
}

static int
ja4_build_exts_list(struct ws *ws, const int *ext_types, size_t ext_count_total,
    int sorted, int exclude_sni_alpn, char **out)
{
	size_t ext_count;
	size_t ei, ej;
	int *exts;

	ext_count = 0;
	for (ei = 0; ei < ext_count_total; ei++) {
		if (!IS_GREASE_TLS(ext_types[ei]) &&
		    (!exclude_sni_alpn ||
		    (ext_types[ei] != TLSEXT_TYPE_server_name &&
		    ext_types[ei] != TLSEXT_TYPE_alpn)))
			ext_count++;
	}
	*out = WS_Alloc(ws, 1);
	if (*out == NULL)
		return (-1);
	**out = '\0';
	if (ext_count == 0)
		return (0);
	exts = WS_Alloc(ws, ext_count * sizeof(int));
	if (exts == NULL)
		return (-1);
	for (ei = 0, ej = 0; ei < ext_count_total; ei++) {
		if (!IS_GREASE_TLS(ext_types[ei]) &&
		    (!exclude_sni_alpn ||
		    (ext_types[ei] != TLSEXT_TYPE_server_name &&
		    ext_types[ei] != TLSEXT_TYPE_alpn)))
			exts[ej++] = ext_types[ei];
	}
	if (sorted)
		qsort(exts, ext_count, sizeof(int), cmp_int);
	*out = ja4_format_hex_list_int(ws, exts, ext_count);
	return (*out == NULL ? -1 : 0);
}

static int
ja4_exts_sigs_hash(struct ws *ws, const char *exts_str, const char *sig_algs,
    char out[JA4_HASH_BUF])
{
	size_t exts_len, sig_len, total;
	char *combined = NULL;

	exts_len = strlen_safe(exts_str);
	sig_len = strlen_safe(sig_algs);

	if (exts_len == 0 && sig_len == 0) {
		vtls_ja4_hash12("", 0, out);
		return (0);
	}
	total = exts_len + (sig_len > 0 ? 1 + sig_len : 0);
	combined = WS_Alloc(ws, total + 1);
	if (combined == NULL)
		return (-1);
	if (exts_len > 0)
		memcpy(combined, exts_str, exts_len + 1);
	else
		combined[0] = '\0';
	if (sig_len > 0) {
		strcat(combined, "_");
		strcat(combined, sig_algs);
	}
	vtls_ja4_hash12(combined, total, out);
	return (0);
}

static char *
ja4_build_raw(struct ws *ws, const char *part_a, const char *ciphers_str,
    const char *exts_str, const char *sig_algs)
{
	size_t l;
	size_t cipher_len, exts_len, sig_len;
	char *out;

	cipher_len = strlen_safe(ciphers_str);
	exts_len = strlen_safe(exts_str);
	sig_len = strlen_safe(sig_algs);

	l = strlen(part_a) + 1 + cipher_len + 1 + exts_len + 1;
	if (sig_len > 0)
		l += 1 + sig_len;
	l++;

	out = WS_Alloc(ws, l);
	if (out == NULL)
		return (NULL);
	if (sig_len > 0)
		sprintf(out, "%s_%s_%s_%s", part_a,
		    ciphers_str ? ciphers_str : "", exts_str ? exts_str : "", sig_algs);
	else
		sprintf(out, "%s_%s_%s", part_a,
		    ciphers_str ? ciphers_str : "", exts_str ? exts_str : "");
	return (out);
}

static void
ja4_build_part_a(const struct ja3_ja4_raw_ch *raw, char part_a[JA4_PART_A_MAX])
{
	unsigned nr_exts_raw, nr_ciphers, nr_exts;
	size_t ei, ci;
	const char *tls_version_str;
	char sni_marker, alpn_first, alpn_last;

	nr_exts_raw = 0;
	for (ei = 0; ei < raw->ext_count; ei++) {
		if (!IS_GREASE_TLS(raw->ext_types[ei]))
			nr_exts_raw++;
	}
	nr_ciphers = 0;
	for (ci = 0; ci + 2 <= raw->cipher_len; ci += 2) {
		if (!IS_GREASE_TLS(vbe16dec(raw->ciphers + ci)))
			nr_ciphers++;
	}
	nr_ciphers = (nr_ciphers > JA4_COUNT_CAP) ? JA4_COUNT_CAP : (unsigned)nr_ciphers;
	nr_exts = (nr_exts_raw > JA4_COUNT_CAP) ? JA4_COUNT_CAP : nr_exts_raw;

	tls_version_str = ja4_version_str_from_raw(raw);
	sni_marker = raw->has_sni ? 'd' : 'i';
	ja4_alpn_first_last_raw(raw->alpn, raw->alpn_len, &alpn_first, &alpn_last);

	sprintf(part_a, "t%s%c%02u%02u%c%c", tls_version_str, sni_marker,
	    nr_ciphers, nr_exts, alpn_first, alpn_last);
}

static char *
ja4_build_hashed_result(struct ws *ws, const char *part_a,
    const char *ciphers_str, const char *exts_str, const char *sig_algs)
{
	char ciphers_hash[JA4_HASH_BUF];
	char exts_sigs_hash[JA4_HASH_BUF];
	char ja4_buf[JA4_RESULT_MAX];
	size_t cipher_len;

	cipher_len = strlen_safe(ciphers_str);
	vtls_ja4_hash12(ciphers_str ? ciphers_str : "", cipher_len, ciphers_hash);
	if (ja4_exts_sigs_hash(ws, exts_str, sig_algs, exts_sigs_hash) != 0)
		return (NULL);
	sprintf(ja4_buf, "%s_%s_%s", part_a, ciphers_hash, exts_sigs_hash);
	return (WS_Copy(ws, ja4_buf, -1));
}

/*
 * Run one JA4 phase: build the intermediates for that variant and store
 * the result in the matching tsp field. Uses session workspace with
 * WS_Reset after each variant so peak usage stays low. REPLACE strdups
 * the result so it survives the reset.
 */
static int
vtls_get_ja4_one_variant(const struct ja3_ja4_raw_ch *raw, struct sess *sp,
    struct vtls_sess *tsp, enum vtls_ja4_variant variant)
{
	struct ws *ws;
	char part_a[JA4_PART_A_MAX];
	char *ciphers = NULL;
	char *exts = NULL;
	char *sig_algs = NULL;
	char *result = NULL;
	uintptr_t sn;
	int sorted;

	ws = sp->ws;
	sn = WS_Snapshot(ws);
	ja4_build_part_a(raw, part_a);

	/* MAIN,R = sorted; O,RO = original. MAIN,O = hashed; R,RO = raw. */
	sorted = (variant <= VTLS_JA4_R);
	if (ja4_build_cipher_list_raw(ws, raw->ciphers, raw->cipher_len,
	    sorted, &ciphers) != 0)
		goto fail;
	if (ja4_build_exts_list(ws, raw->ext_types, raw->ext_count,
	    sorted, sorted, &exts) != 0)
		goto fail;
	if (ja4_build_sig_algs_str_raw(ws, raw->sig_algs, raw->sig_algs_len,
	    &sig_algs) != 0)
		goto fail;

	result = (variant & 1) == 0
	    ? ja4_build_hashed_result(ws, part_a, ciphers, exts, sig_algs)
	    : ja4_build_raw(ws, part_a, ciphers, exts, sig_algs);
	if (result == NULL)
		goto fail;

	switch (variant) {
	case VTLS_JA4_MAIN:
		REPLACE(tsp->ja4, result);
		break;
	case VTLS_JA4_R:
		REPLACE(tsp->ja4_r, result);
		break;
	case VTLS_JA4_O:
		REPLACE(tsp->ja4_o, result);
		break;
	case VTLS_JA4_RO:
		REPLACE(tsp->ja4_ro, result);
		break;
	}
	WS_Reset(ws, sn);
	return (0);
fail:
	VTLS_LOG(tsp->log, SLT_Error,
	    "Out of workspace_session during JA4 handling");
	WS_Reset(ws, sn);
	return (1);
}

int
VTLS_fingerprint_get_ja4_variant(struct sess *sp, struct vtls_sess *tsp,
    enum vtls_ja4_variant variant)
{
	char **field;

	if (tsp->ja3_ja4_raw == NULL)
		return (-1);
	switch (variant) {
	case VTLS_JA4_MAIN: field = &tsp->ja4; break;
	case VTLS_JA4_R:   field = &tsp->ja4_r; break;
	case VTLS_JA4_O:   field = &tsp->ja4_o; break;
	case VTLS_JA4_RO:  field = &tsp->ja4_ro; break;
	default: return (-1);
	}
	if (*field != NULL)
		return (0);
	return (vtls_get_ja4_one_variant(tsp->ja3_ja4_raw, sp, tsp, variant));
}

/*
 * Compute all four JA4 variants one at a time with WS_Reset between each
 * so peak workspace stays low (one variant's intermediates only).
 */
static int
vtls_get_ja4_from_raw(const struct ja3_ja4_raw_ch *raw, struct sess *sp,
    struct vtls_sess *tsp)
{
	enum vtls_ja4_variant v;

	for (v = VTLS_JA4_MAIN; v <= VTLS_JA4_RO; v++) {
		if (vtls_get_ja4_one_variant(raw, sp, tsp, v) != 0)
			return (1);
	}
	return (0);
}

static int
vtls_get_ja4(SSL *ssl, struct sess *sp, struct vtls_sess *tsp)
{
	(void)ssl;
	if (tsp->ja3_ja4_raw == NULL)
		return (0);
	return (vtls_get_ja4_from_raw(tsp->ja3_ja4_raw, sp, tsp));
}

void
VTLS_fingerprint_raw_free(void **praw)
{
	if (praw == NULL || *praw == NULL)
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

int
VTLS_fingerprint_get_ja3(SSL *ssl, struct sess *sp, struct vtls_sess *tsp)
{
	return (vtls_get_ja3(ssl, sp, tsp));
}

int
VTLS_fingerprint_get_ja4(SSL *ssl, struct sess *sp, struct vtls_sess *tsp)
{
	return (vtls_get_ja4(ssl, sp, tsp));
}
