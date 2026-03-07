/*-
 * Copyright (c) 2020 Varnish Software AS
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
 * TLS protocol version definitions
 *
 * VTLS_PROTO(varnish_proto_name, bitmask_value, openssl_version, string_name)
 */

VTLS_PROTO(SSLv3_PROTO,   0x01, SSL3_VERSION,   "SSLv3")
VTLS_PROTO(TLSv1_0_PROTO, 0x02, TLS1_VERSION,   "TLSv1.0")
VTLS_PROTO(TLSv1_1_PROTO, 0x04, TLS1_1_VERSION, "TLSv1.1")
VTLS_PROTO(TLSv1_2_PROTO, 0x08, TLS1_2_VERSION, "TLSv1.2")
VTLS_PROTO(TLSv1_3_PROTO, 0x10, TLS1_3_VERSION, "TLSv1.3")
