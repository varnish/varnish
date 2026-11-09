/*-
 * Copyright 2026 UPLEX - Nils Goroll Systemtoptimierung
 * All rights reserved.
 *
 * Author: Nils Goroll <nils.goroll@uplex.de>
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
 * Mocking for minimal VDPIO testing
 */

// specific additional error test case
struct vdpio_tc {
	const char		*name;
	const char		*data;
	ssize_t			datasz;
	int			ret;
};

struct vdpio_test {
	unsigned		magic;
#define VDPIO_TEST_MAGIC	0x5de73d14

	unsigned		no_injection;

	const struct vdp	*vdp;
	void			*vdp_priv;

	const char		*data;
	ssize_t			datasz;

	const char		*expect;
	ssize_t			expectsz;

	// output expected for the empty input
	const char		*expect_empty;
	ssize_t			expectsz_empty;

	// specific test cases
	unsigned		capacity;
	unsigned		used;
	struct vdpio_tc		tc[] v_counted_by_(capacity);
};

int vdpio_mock(const struct vdpio_test *);
