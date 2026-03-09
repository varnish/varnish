..
	Copyright (c) 2010-2020 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license

.. role:: ref(emphasis)

.. _vinyltest(1):

=========
vinyltest
=========

----------------------------
Test program for Vinyl Cache
----------------------------

:Manual section: 1

SYNOPSIS
========

vinyltest [-hikLlqv] [-b size] [-D name=val] [-j jobs] [-n iter] [-t duration] file [file ...]

DESCRIPTION
===========

The `vinyltest` program is a script driven program used to test the
Vinyl Cache.

The `vinyltest` program, when started and given one or more script
files, can create a number of threads representing backends, some
threads representing clients, and a `vinyld` process. This is then used to
simulate a transaction to provoke a specific behavior.

The following options are available:

-b size          Set internal buffer size (default: 1M)

-D name=val      Define macro for use in scripts

-h               Show help

-i               Set PATH and vmod_path to find Vinyl Cache binaries in build tree

-j jobs          Run this many tests in parallel

-k               Continue on test failure

-L               Always leave temporary vtc.*

-l               Leave temporary vtc.* if test fails

-n iterations    Run tests this many times

-p name=val      Pass parameters to all `vinyld` command lines

-q               Quiet mode: report only failures

-t duration      Time tests out after this long (default: 60s)

-v               Verbose mode: always report test log

file             File to use as a script


If `TMPDIR` is set in the environment, `vinyltest` creates temporary
`vtc.*` directories for each test in `$TMPDIR`, otherwise in `/tmp`.

SCRIPTS
=======

The vtc syntax is documented at length in :ref:`vtc(7)`. Should you want more
examples than the one below, you can have a look at the Vinyl Cache source code
repository, under `bin/vinyltest/tests/`, where all the regression tests for
Vinyl Cache are kept.

An example::

        vinyltest "#1029"

        server s1 {
                rxreq
                expect req.url == "/bar"
                txresp -gzipbody {[bar]}

                rxreq
                expect req.url == "/foo"
                txresp -body {<h1>FOO<esi:include src="/bar"/>BARF</h1>}

        } -start

        vinyl v1 -vcl+backend {
                sub vcl_backend_response {
                        set beresp.do_esi = true;
                        if (bereq.url == "/foo") {
                                set beresp.ttl = 0s;
                        } else {
                                set beresp.ttl = 10m;
                        }
                }
        } -start

        client c1 {
                txreq -url "/bar" -hdr "Accept-Encoding: gzip"
                rxresp
                gunzip
                expect resp.bodylen == 5

                txreq -url "/foo" -hdr "Accept-Encoding: gzip"
                rxresp
                expect resp.bodylen == 21
        } -run

When run, the above script will simulate a server (s1) that expects
two different requests. It will start a `vinyld` (v1) and add the
backend definition to the VCL specified (-vcl+backend). Finally it starts
the c1-client, which is a single client sending two requests.

TESTING A BUILD TREE
====================

Whether you are building a VMOD or trying to use one that you freshly
built, you can tell ``vinyltest`` to pass a *vmod_path* to ``vinyld``
instances started using the ``vinyl -start`` command in your test case::

    vinyltest -p vmod_path=... /path/to/*.vtc

This way you can use the same test cases on both installed and built
VMODs::

    server s1 {...} -start

    vinyl v1 -vcl+backend {
        import wossname;

        ...
    } -start

    ...

You are not limited to the *vmod_path* and can pass any parameter,
allowing you to run a build matrix without changing the test suite. You
can achieve the same with macros, but then they need to be defined on
each run.

You can see the actual ``vinyld`` command lines in test outputs,
they look roughly like this::

    exec vinyld [vinyltest -p params] [testing params] [vtc -arg params]

Parameters you define with ``vinyltest -p`` may be overridden by
parameters needed by ``vinyltest`` to run properly, and they may in
turn be overridden by parameters set in test scripts.

There's also a special mode in which ``vinyltest`` builds itself a
PATH and a *vmod_path* in order to find Vinyl Cache binaries (programs and
VMODs) in the build tree surrounding the ``vinyltest`` binary. This
is meant for testing of Vinyl Cache under development and will disregard
your *vmod_path* if you set one.

If you need to test your VMOD against a Vinyl Cache build tree, you must
install it first, in a temp directory for instance. With information
provided by the installation's *pkg-config(1)* you can build a proper
PATH in order to access Vinyl programs, and a *vmod_path* to access
both your VMOD and the built-in VMODs::

    export PKG_CONFIG_PATH=/path/to/install/lib/pkgconfig

    BINDIR="$(pkg-config --variable=bindir vinylapi)"
    SBINDIR="$(pkg-config --variable=sbindir vinylapi)"
    PATH="SBINDIR:BINDIR:$PATH"

    VMODDIR="$(pkg-config --variable=vmoddir vinylapi)"
    VMOD_PATH="/path/to/your/vmod/build/dir:$VMODDIR"

    vinyltest -p vmod_path="$VMOD_PATH" ...

SEE ALSO
========

* vinyltest source code repository with tests
* :ref:`vinylhist(1)`
* :ref:`vinyllog(1)`
* :ref:`vinylncsa(1)`
* :ref:`vinylstat(1)`
* :ref:`vinyltop(1)`
* :ref:`vcl(7)`
* :ref:`vtc(7)`
* :ref:`vmod_vtc(3)`

HISTORY
=======

The vinyltest program was developed by Poul-Henning Kamp
<phk@phk.freebsd.dk> in cooperation with Redpill-Linpro.  This manual
page was originally written by Stig Sandbeck Mathisen <ssm@linpro.no>
and updated by Kristian Lyngstøl <kristian@varnish-cache.org>.


COPYRIGHT
=========

This document is licensed under the same licence as Vinyl Cache
itself. See LICENCE for details.

* Copyright (c) 2007-2016 Varnish Software AS
