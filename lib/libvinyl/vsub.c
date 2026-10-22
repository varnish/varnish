/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
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
 * Run stuff in a child process
 */

#include "config.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>		// Solaris closefrom(3c)
#include <string.h>
#include <unistd.h>		// BSD/Linux close_range(2)
#ifndef HAVE_CLOSEFROM
#  include <dirent.h>
#endif

#include "vdef.h"

#include "vapi/vsig.h"

#include "vas.h"
#include "vfil.h"
#include "vlu.h"
#include "vsb.h"
#include "vsub.h"
#include "vtim.h"

struct vsub_priv {
	const char	*name;
	struct vsb	*sb;
	int		lines;
	int		maxlines;
};

void
VSUB_closefrom(int fd)
{

	assert(fd >= 0);

#ifdef HAVE_CLOSEFROM
	closefrom(fd);
	return;
#else
#  ifdef HAVE_WORKING_CLOSE_RANGE
	if (close_range(fd, ~0U, 0) == 0)
		return;
#  endif
	char buf[128];
	int i;
	DIR *d;
	struct dirent *de;
	char *p;

	bprintf(buf, "/proc/%d/fd/", getpid());
	d = opendir(buf);
	if (d != NULL) {
		while (1) {
			de = readdir(d);
			if (de == NULL)
				break;
			i = strtoul(de->d_name, &p, 10);
			if (*p != '\0' || i <= fd || i == dirfd(d))
				continue;
			(void)close(i);
		}
		AZ(closedir(d));
	} else {
		/* NB: Very slow if called with a high FD limit */
		i = sysconf(_SC_OPEN_MAX);
		assert(i > 0);
		for (; i > fd; i--)
			(void)close(i);
	}
#endif
}

static int
vsub_vlu(void *priv, const char *str)
{
	struct vsub_priv *sp;

	sp = priv;
	if (!sp->lines++)
		VSB_printf(sp->sb, "Message from %s:\n", sp->name);
	if (sp->maxlines < 0 || sp->lines <= sp->maxlines)
		VSB_printf(sp->sb, "%s\n", str);
	return (0);
}

/*
 * Read the child's output until EOF or until the deadline.  Returns 1 on
 * timeout, -1 on poll() failure (errno is preserved), 0 otherwise.  Note that EOF only happens once all holders of the write side
 * of the pipe are gone, so a descendant of the child can trigger a timeout
 * even after the child itself has exited.
 */
static int
vsub_read_tmo(int fd, struct vsub_priv *sp, vtim_dur tmo)
{
	struct vlu *vlu;
	struct pollfd pfd;
	vtim_mono end;
	int i, t, rv = 0;
	double d;

	vlu = VLU_New(vsub_vlu, sp, 0);
	AN(vlu);
	end = VTIM_mono() + tmo;
	pfd.fd = fd;
	pfd.events = POLLIN;
	while (1) {
		d = (end - VTIM_mono()) * 1000.0;
		if (d < 1.0) {
			rv = 1;
			break;
		}
		t = d > 1e9 ? 1000000000 : (int)d;
		pfd.revents = 0;
		i = poll(&pfd, 1, t);
		if (i < 0 && errno == EINTR)
			continue;
		if (i < 0) {
			rv = -1;
			break;
		}
		if (i == 0)
			continue;
		if (VLU_Fd(vlu, fd) != 0)
			break;
	}
	i = errno;
	VLU_Destroy(&vlu);
	errno = i;
	return (rv);
}

/* returns an exit code */
unsigned
VSUB_run(struct vsb *sb, vsub_func_f *func, void *priv, const char *name,
    int maxlines)
{

	return (VSUB_run_tmo(sb, func, priv, name, maxlines, 0));
}

/* returns an exit code, tmo <= 0 means no deadline */
unsigned
VSUB_run_tmo(struct vsb *sb, vsub_func_f *func, void *priv, const char *name,
    int maxlines, vtim_dur tmo)
{
	int rv, p[2], status, timed_out = 0;
	pid_t pid;
	struct vsub_priv sp;

	sp.sb = sb;
	sp.name = name;
	sp.lines = 0;
	sp.maxlines = maxlines;

	if (pipe(p) < 0) {
		VSB_printf(sb, "Starting %s: pipe() failed: %s",
		    name, strerror(errno));
		return (1);
	}
	assert(p[0] > STDERR_FILENO);
	assert(p[1] > STDERR_FILENO);
	if ((pid = fork()) < 0) {
		VSB_printf(sb, "Starting %s: fork() failed: %s",
		    name, strerror(errno));
		closefd(&p[0]);
		closefd(&p[1]);
		return (1);
	}
	if (pid == 0) {
		if (tmo > 0)
			(void)setpgid(0, 0);
		VFIL_null_fd(STDIN_FILENO);
		assert(dup2(p[1], STDOUT_FILENO) == STDOUT_FILENO);
		assert(dup2(p[1], STDERR_FILENO) == STDERR_FILENO);
		/* Close all other fds */
		VSUB_closefrom(STDERR_FILENO + 1);
		func(priv);
		/*
		 * func should either exec or exit, so getting here should be
		 * treated like an assertion failure - except that we don't know
		 * if it's safe to trigger an actual assertion
		 */
		_exit(4);
	}
	closefd(&p[1]);
	if (tmo > 0) {
		/* Also done by the child, whichever gets there first wins */
		if (setpgid(pid, pid) < 0)
			assert(errno == EACCES || errno == ESRCH);
		timed_out = vsub_read_tmo(p[0], &sp, tmo);
		if (timed_out != 0) {
			(void)kill(-pid, SIGKILL);
			if (timed_out > 0)
				VSB_printf(sb,
				    "Running %s timed out after %.1fs\n",
				    name, tmo);
			else
				VSB_printf(sb, "Running %s: poll() failed: "
				    "%s\n", name, strerror(errno));
		}
	} else
		(void)VLU_File(p[0], vsub_vlu, &sp, 0);
	closefd(&p[0]);
	if (sp.maxlines >= 0 && sp.lines > sp.maxlines)
		VSB_printf(sb, "[%d lines truncated]\n",
		    sp.lines - sp.maxlines);
	do {
		rv = waitpid(pid, &status, 0);
		if (rv < 0 && errno != EINTR) {
			VSB_printf(sb, "Running %s: waitpid() failed: %s\n",
			    name, strerror(errno));
			return (1);
		}
	} while (rv < 0);
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		rv = -1;
		VSB_printf(sb, "Running %s failed", name);
		if (WIFEXITED(status)) {
			rv = WEXITSTATUS(status);
			VSB_printf(sb, ", exited with %d", rv);
		}
		if (WIFSIGNALED(status)) {
			rv = 2;
			VSB_printf(sb, ", signal %d", WTERMSIG(status));
		}
		if (WCOREDUMP(status))
			VSB_cat(sb, ", core dumped");
		VSB_cat(sb, "\n");
		assert(rv != -1);
		return (rv);
	}
	return (timed_out != 0 ? 1 : 0);
}

#ifdef TEST_DRIVER

static void
run_sh(void *priv)
{

	(void)execl("/bin/sh", "sh", "-c", (const char *)priv, (char *)NULL);
}

static int
check(const char *script, vtim_dur tmo, int expect, const char *needle,
    int limit)
{
	struct vsb *sb;
	vtim_mono t0;
	unsigned r;
	int fail = 0;

	sb = VSB_new_auto();
	AN(sb);
	t0 = VTIM_mono();
	r = VSUB_run_tmo(sb, run_sh, TRUST_ME(script), "test", -1, tmo);
	t0 = VTIM_mono() - t0;
	AZ(VSB_finish(sb));
	if (expect >= 0 ? (int)r != expect : r == 0) {
		fprintf(stderr, "'%s': bad return %u\n", script, r);
		fail = 1;
	}
	if (strstr(VSB_data(sb), needle) == NULL) {
		fprintf(stderr, "'%s': missing '%s' in '%s'\n", script,
		    needle, VSB_data(sb));
		fail = 1;
	}
	if (limit > 0 && t0 >= limit) {
		fprintf(stderr, "'%s': took %.1fs\n", script, t0);
		fail = 1;
	}
	VSB_destroy(&sb);
	return (fail);
}

int
main(int argc, char **argv)
{
	int fail = 0;

	(void)argc;
	(void)argv;

	fail |= check("echo hello", 5, 0, "hello", 0);
	fail |= check("exit 3", 0, 3, "exited with 3", 0);
	fail |= check("exec sleep 30", 0.5, -1, "timed out", 5);
	fail |= check("sleep 30 & exit 0", 0.5, -1, "timed out", 5);
	return (fail);
}
#endif /* TEST_DRIVER */
