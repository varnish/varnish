/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * TLS client fingerprinting (JA3/JA4) API.
 * Opaque raw Client Hello blob; implementation in cache_tls_fingerprint.c.
 */

#include <openssl/ssl.h>
#include <stddef.h>

/* Max Client Hello size we accept (TLS 1.3 record payload max); reject larger. */
#define VTLS_CLIENT_HELLO_MAX_LEN	16384

#define IS_GREASE_TLS(x) \
	((((x) & 0x0f0f) == 0x0a0a) && (((x) & 0xff) == (((x) >> 8) & 0xff)))

struct sess;
struct vtls_sess;

/* Free raw Client Hello blob; sets *praw = NULL. Safe if *praw == NULL. */
void VTLS_fingerprint_raw_free(void **praw);

/* Parse Client Hello into *out_raw. On success *out_raw is set and 0 returned; on failure -1. */
int VTLS_fingerprint_parse_clienthello(const unsigned char *buf, size_t len,
    void **out_raw);

/* Compute JA3 from tsp->ja3_ja4_raw into tsp->ja3. Returns 0 on success. */
int VTLS_fingerprint_get_ja3(SSL *ssl, struct sess *sp, struct vtls_sess *tsp);

/* JA4 dimensions (bitfield): sorted vs original order, hashed vs raw. */
#define VTLS_JA4_SORTED	0x01u
#define VTLS_JA4_HASHED	0x02u

/* Convenience: which JA4 variant to compute (combination of the two bits above). */
#define VTLS_JA4_MAIN	(VTLS_JA4_SORTED | VTLS_JA4_HASHED)	/* ja4 */
#define VTLS_JA4_R	(VTLS_JA4_SORTED)				/* ja4_r */
#define VTLS_JA4_O	(VTLS_JA4_HASHED)				/* ja4_o */
#define VTLS_JA4_RO	0u						/* ja4_ro */

/* Compute one JA4 variant from tsp->ja3_ja4_raw into the matching tsp field.
 * variant uses VTLS_JA4_SORTED and/or VTLS_JA4_HASHED. Returns 0 on success. */
int VTLS_fingerprint_get_ja4_variant(struct sess *sp, struct vtls_sess *tsp,
    unsigned variant);
