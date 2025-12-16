/*-
 * Copyright (c) 2018 Varnish Software AS
 * All rights reserved.
 *
 * Author: Dag Haavi Finstad <daghf@varnish-software.com>
 * Author: Dridi Boukelmoune <dridi.boukelmoune@gmail.com>
 * Author: Martin Blix Grydeland <martin@varnish-software.com>
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
 * Abstract Connection operations
 *
 */

typedef ssize_t vco_read_f(void *, int, void *, size_t);
typedef ssize_t vco_write_f(void *, int, const void *, size_t);
typedef void vco_writev_prep_f(void *, struct worker *);
typedef ssize_t vco_writev_f(void *, int, const struct iovec *, int);
typedef ssize_t vco_nb_read_f(void *, int, void *, size_t, vtim_real);
typedef ssize_t vco_nb_writev_f(void *, int, const struct iovec *, int,
    vtim_real);
typedef int vco_check_f(ssize_t);

struct vco {
	vco_read_f		*read;
	vco_write_f		*write;
	vco_writev_prep_f	*writev_prep;
	vco_writev_f		*writev;
	vco_nb_read_f		*nb_read;
	vco_nb_writev_f		*nb_writev;
	vco_check_f		*check;
};

#define VCO_Assert(vco, a)	assert((vco)->check(a))

extern const struct vco *VCO_default;
