/*-
 * Copyright 2025 UPLEX - Nils Goroll Systemoptimierung
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
 * Wrapper to call vtest with additional extensions
 *
 * The problem solved by this code can easily also be solved with a two-liner
 * shell script, except that we would need to implement all the mechanics to
 * locate libvtest_ext_varnish.so while it is still uninstalled. But for this
 * simple program, libtool handles it all.
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "vdef.h"

#define EXTVARNISH "libvtest_ext_varnish.so"

const char *args_native[]= {
	"vtest",
	"-E", EXTVARNISH,
};

const char *args_automake[]= {
	"vtest",
	"--extension", EXTVARNISH,
};

struct addargs {
	const char **args;
	size_t n;
};

struct addargs addargs_native = {
	.args = args_native,
	.n = vcountof(args_native)
};

struct addargs addargs_automake = {
	.args = args_automake,
	.n = vcountof(args_automake)
};

static char **
addargs(int argc, char **argv, const struct addargs *add)
{
	char **narg = calloc(argc + add->n, sizeof *narg);

	assert(argc > 0);

	if (narg == NULL)
		return (NULL);

	memcpy(&narg[0], add->args, add->n * sizeof *narg);
	memcpy(&narg[add->n], &argv[1], (argc - 1) * sizeof *narg);

	return (narg);
}

// XXX
//#define LIBDIR "wrogn"

#define LDP "LD_LIBRARY_PATH"
#ifndef LIBDIR
#error "LIBDIR needs to be defined"
#endif

int
main(int argc, char **argv)
{
	char **narg;
	char *ldp;
	int r;

	if (argc >= 2 && !strncmp(argv[1], "--", 2))
		narg = addargs(argc, argv, &addargs_automake);
	else
		narg = addargs(argc, argv, &addargs_native);

	if (narg == NULL)
		return (ENOMEM);

        /* the LD_LIBRARY_PATH de-tour is to enable override for an in-tree
         * varnishtest during build. The same could be achieved by setting RPATH
         * (not RUNPATH) for libvtest_ext_varnish.so, but support for it is being
         * phased out by linkers.
         */

	if ((ldp = getenv(LDP)) == NULL)
		setenv(LDP, LIBDIR, 1);
	else {
		// append LIBDIR such that an external env has precedence
		char *nldp = malloc(strlen(ldp) + strlen(LIBDIR ":") + 1);
		assert(nldp != NULL);
		(void)strcat(nldp, ldp);
		(void)strcat(nldp, ":" LIBDIR);
		setenv(LDP, nldp, 1);
		free(nldp);
	}

	r = execvp(narg[0], narg);
	fprintf(stderr, "execvp(%s): %d (%s)\n", narg[0], errno,
		strerror(errno));
	return (r);
}
