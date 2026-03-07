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
 * Abstract TCP operations
 *
 */

#include "config.h"

#include <sys/uio.h>
#include <unistd.h>
#include <errno.h>

#include "cache/cache_varnishd.h"
#include "cache/cache_conn_oper.h"

#include "vtcp.h"

static ssize_t v_matchproto_(vco_read_f)
vco_read(void *priv, int fd, void *buf, size_t len)
{
	int i;

	assert(fd >= 0);
	(void)priv;

	i = read(fd, buf, len);
	if (i < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		i = -2;
	return (i);
}

static ssize_t v_matchproto_(vco_write_f)
vco_write(void *priv, int fd, const void *buf, size_t len)
{

	assert(fd >= 0);
	(void)priv;

	return (write(fd, buf, len));
}

static ssize_t v_matchproto_(vco_writev_f)
vco_writev(void *priv, int fd, const struct iovec *iov, int count)
{

	assert(fd >= 0);
	AN(iov);
	AN(count);
	(void)priv;

	return (writev(fd, iov, count));
}

static ssize_t v_matchproto_(vco_nb_read_f)
vco_nb_read(void *priv, int fd, void *buf, size_t len, vtim_real deadline)
{
	(void)priv;
	assert(fd >= 0);

	/* Note: The deadline argument is for use with TLS when the
	 * library demands writes during reads. It is not used for
	 * unencrypted sockets. */
	(void)deadline;

	return (read(fd, buf, len));
}

static ssize_t v_matchproto_(vco_nb_write_f)
vco_nb_writev(void *priv, int fd, const struct iovec *iov, int n_iov,
    vtim_real deadline)
{
	(void)priv;
	assert(fd >= 0);

	/* Note: The deadline argument is for use with TLS when the
	 * library demands writes during reads. It is not used for
	 * unencrypted sockets. */
	(void)deadline;

	return (writev(fd, iov, n_iov));
}

static int v_matchproto_(vco_check_f)
vco_check(ssize_t a)
{

	return (VTCP_Check(a));
}

static const struct vco vco_default = {
	.read = vco_read,
	.write = vco_write,
	.writev_prep = NULL,
	.writev = vco_writev,
	.nb_read = vco_nb_read,
	.nb_writev = vco_nb_writev,
	.check = vco_check,
};

const struct vco *VCO_default = &vco_default;
