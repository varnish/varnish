**Note: This is a working document for a future release, with running
updates for changes in the development branch. For changes in the
released versions of Varnish, see:** :ref:`whats-new-index`

.. _whatsnew_changes_CURRENT:

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Changes in Varnish **$NEXT_RELEASE**
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

This release can be summarized as **improved protocol handling and
bugfixes**.

When upgrading, we strongly recommend reading
:ref:`whatsnew_upgrading_CURRENT`, because some changes should not remain
unnoticed. We did not consider any of them breaking enough to warrant a
major version bump, but they might still be relevant.

A more detailed and technical account of changes in Varnish, with
links to issues that have been fixed and pull requests that have been
merged, may be found in the `change log`_.

.. _change log: https://github.com/varnish/varnish/blob/master/doc/changes.rst

varnishd
========

Worker pools are now shut down during a worker process stop as initiated by
``varnishadm stop``. This improves shutdown speed by releasing VCL references
earlier.

Protocol framing fixes
~~~~~~~~~~~~~~~~~~~~~~

HTTP/1 message framing checks have been tightened:

- Backend responses with invalid body framing now fail the fetch.

- Multiple ``Transfer-Encoding`` fields are now considered as a whole, such that
  duplicate ``chunked`` codings are refused.

- Multiple ``Content-Length`` fields and values are now accepted if they all
  agree (leading zeroes are tolerated) and consolidated into a single canonical
  header, any disagreement is refused.

- ``Transfer-Encoding`` on an HTTP/1.0 request is now refused.

- The backend connection is now closed when the range check of a response
  fails, to avoid reusing a connection with an unread body.

- An existing, correct ``Connection`` response header is no longer overwritten
  when closing: other tokens are preserved and ``close`` or ``keep-alive`` are
  added as needed. If a ``Connection`` was not present, or was incorrect, we
  create a new, correct one.

Changes to VCL
==============

Other changes to VCL
~~~~~~~~~~~~~~~~~~~~

Range processing is now only applied to ``GET`` requests as mandated by RFC
9110, and the builtin VCL removes the ``Range`` header from other requests.

The HTTP ``QUERY`` method has been added to the well known request methods
and is passed by default in the builtin VCL.

Changes to bundled VMODs
========================

``std.getenv()`` gained an optional *fallback* argument which is returned if
the environment variable is not set.

The argument to ``std.rollback()`` is now obsolete and ignored, the appropriate
headers to be rolled back are now inferred from the call site. This also fixes
a panic when ``resp`` or ``beresp`` was passed.

``std.collect_all()`` has been added to combine all multiple headers of
``req``, ``resp``, ``bereq`` or ``beresp`` according to the HTTP RFCs:
``Set-Cookie`` is not combined, ``Cookie`` is combined with ``"; "`` and all
other headers with ``", "``.

VSL (varnishlog, varnishncsa)
==============================

These changes concern log processing in general, so they also affect other VSL
processing tools.

Malformed lines in the VSM ``_.index`` file are now reported with a
meaningful diagnostic instead of a bare assertion failure in VSM readers like
``varnishstat`` and ``varnishlog``.

varnishadm
==========

The ``-x workdir`` option has been added to ``varnishadm`` to print the default
work directory and exit. This is useful for tools that need to discover the VSM
location in most setups.

``varnishadm`` now only uses libedit if both stdin and stdout are terminals.

``varnishd`` now checks for an already running instance before modifying the
working directory.

VSC (varnishstat)
=================

These changes concern counters in general, so they also affect other VSC
processing tools.

Counters for backend connection closes have been added:
``MAIN.backend_closed``, ``MAIN.backend_closed_err`` and the equivalent
per-backend ``VBE.*.closed`` and ``VBE.*.closed_err`` counters.

varnishtest / vtest
====================

Varnish can now be built without the vtest2 git submodule and instead with
an externally provided vtest program, as installed by running ``DESTDIR=/prefix
make install`` in the Vtest2 repository
https://code.vinyl-cache.org/vtest/VTest2

The Varnish specific test commands ``varnish``, ``logexpect`` and ``vsm`` have
been moved to a vtest extension.

For a build *with* the submodule, both a ``varnishtest`` program and ``vtest``
symlink continue to be built and installed as monolithic binaries which always
include the extension.

For a build *without* the submodule (with an external ``vtest`` program), a
``varnishtest`` wrapper is built, which sets up the right command line
arguments and calls ``vtest``.

The following vtest ``feature`` tests have been moved to ``vcache_builtwith`` in
the Varnish VTest extension: ``64bit``, ``persistent_storage``, ``coverage``,
``asan``, ``msan``, ``tsan``, ``ubsan``, ``sanitizer``, ``workspace_emulator``
and ``witness``.

The Varnish VTest extension also gained the ``VTEST_VARNISH_VCL_PREPEND``
environment variable to inject VCL code into all VCL loaded by ``varnish``
instances.

Changes for developers and VMOD authors
=======================================

VMOD builds
~~~~~~~~~~~

We added infrastructure to easily build VMODs for multiple VCache based
projects (Varnish, Vinyl Cache, and others). Besides changing how VMOD builds
discover such projects and configure themselves appropriately, we also added
the ``vcache`` command to the Varnish VTest extension.

See :ref:`ref-vmod-vcache` for details on how to migrate.

The ``varnish-legacy.m4`` macro collection for VMOD builds has been removed.
VMODs should migrate to using the macros from ``varnish.m4``.

Changes for package maintainers
================================

The default for ``VARNISH_STATE_DIR`` has been changed back to
``${localstatedir}/varnish``.

During build, the new ``configure`` option ``--with-statedir`` now allows to
set the ``VARNISH_STATE_DIR`` directly, which is the default for
``VARNISH_DEFAULT_N``, which, in turn, is the default for the ``-n`` argument
to ``varnishd`` and ``varnish{log,ncsa,hist,top}``.

Changes for downstream project maintainers
===========================================

We ask you to adopt the new ``varnish.m4`` for your project under the name of
your project. This is vital to achieve the goal of enabling VMOD authors to
easily support multiple VCache based projects.

Please also read :ref:`ref-vmod-vcache` to understand the background.

*eof*
