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
	unsigned long	lines;
	int		maxlines;
	size_t		bytes;
	size_t		maxbytes;
	int		truncated;
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
	size_t l;

	sp = priv;
	if (!sp->lines++)
		VSB_printf(sp->sb, "Message from %s:\n", sp->name);
	if (sp->maxlines >= 0 && sp->lines > (unsigned)sp->maxlines)
		return (0);
	if (sp->maxbytes > 0) {
		/* Only ever keep a prefix of the output */
		if (sp->truncated)
			return (0);
		l = strlen(str) + 1;
		if (l > sp->maxbytes - sp->bytes) {
			sp->truncated = 1;
			return (0);
		}
		sp->bytes += l;
	}
	VSB_printf(sp->sb, "%s\n", str);
	return (0);
}

/*
 * Read the child's output until EOF or until the deadline.  Returns 1 on
 * timeout, -1 on poll() failure (errno is preserved), 0 otherwise.
 * Note that EOF only happens once all holders of the write side of the
 * pipe are gone, so a descendant of the child can trigger a timeout even
 * after the child itself has exited.
 */
static int
vsub_read_tmo(int fd, struct vsub_priv *sp, vtim_mono end)
{
	struct vlu *vlu;
	struct pollfd pfd;
	int i, t, rv = 0;
	double d;

	vlu = VLU_New(vsub_vlu, sp, 0);
	AN(vlu);
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

/*
 * Reap the child, but give up at the deadline: closing (or redirecting)
 * its output does not mean it is done.  Returns 1 on timeout, 0 if the
 * child was reaped or waitpid() failed (*reaped tells which).
 */
static int
vsub_wait_tmo(pid_t pid, int *status, int *reaped, vtim_mono end)
{
	vtim_dur d, nap = 0.001;
	pid_t rv;

	*reaped = 0;
	while (1) {
		rv = waitpid(pid, status, WNOHANG);
		if (rv == pid) {
			*reaped = 1;
			return (0);
		}
		if (rv < 0 && errno != EINTR)
			return (0);
		d = end - VTIM_mono();
		if (d <= 0)
			return (1);
		VTIM_sleep(nap < d ? nap : d);
		if (nap < 0.05)
			nap *= 2;
	}
}

/* returns an exit code */
unsigned
VSUB_run(struct vsb *sb, vsub_func_f *func, void *priv, const char *name,
    int maxlines)
{

	return (VSUB_run_tmo(sb, func, priv, name, maxlines, 0, 0));
}

/*
 * returns an exit code, tmo <= 0 means no deadline, maxbytes == 0 means
 * no limit on the amount of output kept in sb.
 */
unsigned
VSUB_run_tmo(struct vsb *sb, vsub_func_f *func, void *priv, const char *name,
    int maxlines, vtim_dur tmo, size_t maxbytes)
{
	int rv, p[2], status, timed_out = 0, reaped = 0, e;
	pid_t pid;
	vtim_mono end;
	struct vsub_priv sp;

	memset(&sp, 0, sizeof sp);
	sp.sb = sb;
	sp.name = name;
	sp.maxlines = maxlines;
	sp.maxbytes = maxbytes;

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
		/*
		 * Also done by the child, whichever gets there first wins.
		 * This fails if the child already moved on (exec'ed and
		 * changed its process group or session), which is fine.
		 */
		(void)setpgid(pid, pid);
		end = VTIM_mono() + tmo;
		timed_out = vsub_read_tmo(p[0], &sp, end);
		if (timed_out == 0)
			timed_out = vsub_wait_tmo(pid, &status, &reaped, end);
		if (timed_out != 0) {
			e = errno;
			/*
			 * The child may have left its process group, so
			 * kill it directly too.  It has not been reaped, so
			 * its pid cannot have been reused.
			 */
			(void)kill(-pid, SIGKILL);
			(void)kill(pid, SIGKILL);
			if (timed_out > 0)
				VSB_printf(sb,
				    "Running %s timed out after %.1fs\n",
				    name, tmo);
			else
				VSB_printf(sb, "Running %s: poll() failed: "
				    "%s\n", name, strerror(e));
		}
	} else
		(void)VLU_File(p[0], vsub_vlu, &sp, 0);
	closefd(&p[0]);
	if (sp.maxlines >= 0 && sp.lines > (unsigned)sp.maxlines)
		VSB_printf(sb, "[%lu lines truncated]\n",
		    sp.lines - sp.maxlines);
	if (sp.truncated)
		VSB_cat(sb, "[output truncated]\n");
	while (!reaped) {
		rv = waitpid(pid, &status, 0);
		if (rv < 0 && errno != EINTR) {
			VSB_printf(sb, "Running %s: waitpid() failed: %s\n",
			    name, strerror(errno));
			return (1);
		}
		reaped = (rv == pid);
	}
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

#define ESCAPE_PGRP \
	"perl -e '" \
	"my $c = fork(); defined $c or exit 1;" \
	"if (!$c) { setpgrp(0, 0); exec \"sleep\", \"30\" }" \
	"for (1..1000) { last if getpgrp($c) == $c; select(undef, undef, undef, 0.001) }" \
	"setpgrp(0, $c) or exit 1;" \
	"exec \"sleep\", \"30\"'"

static void
run_sh(void *priv)
{

	(void)execl("/bin/sh", "sh", "-c", (const char *)priv, (char *)NULL);
}

static int
check_cap(const char *script, vtim_dur tmo, int expect, const char *needle,
    int limit, size_t maxbytes)
{
	struct vsb *sb;
	vtim_mono t0;
	unsigned r;
	int fail = 0;

	sb = VSB_new_auto();
	AN(sb);
	t0 = VTIM_mono();
	r = VSUB_run_tmo(sb, run_sh, TRUST_ME(script), "test", -1, tmo,
	    maxbytes);
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
	if (maxbytes > 0 && VSB_len(sb) > maxbytes + 1024) {
		fprintf(stderr, "'%s': %zd bytes of output\n", script,
		    VSB_len(sb));
		fail = 1;
	}
	VSB_destroy(&sb);
	return (fail);
}

static int
check(const char *script, vtim_dur tmo, int expect, const char *needle,
    int limit)
{

	return (check_cap(script, tmo, expect, needle, limit, 0));
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
	/* No output to wait for, the deadline must cover the reaping too */
	fail |= check("exec >/dev/null 2>&1; sleep 30", 0.5, -1,
	    "timed out", 5);
	/* Leave the process group, falls back to a plain sleep without perl */
	fail |= check("exec >/dev/null 2>&1; "
	    "command -v perl >/dev/null && exec " ESCAPE_PGRP "; "
	    "exec sleep 30", 0.5, -1, "timed out", 5);
	fail |= check_cap("yes | head -c 5000000; exit 1", 5, 1,
	    "[output truncated]", 0, 1024 * 1024);
	fail |= check_cap("echo hello", 5, 0, "hello", 0, 1024 * 1024);
	fail |= check_cap("yes | head -c 50000", 5, 0, "[output truncated]",
	    0, 1000);
	return (fail);
}
#endif /* TEST_DRIVER */
