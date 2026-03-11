.. _whatsnew_changes_9.0:

%%%%%%%%%%%%%%%%%%%%
Changes in Vinyl 9.0
%%%%%%%%%%%%%%%%%%%%

For information about updating your current Varnish deployment to the
new version, see :ref:`whatsnew_upgrading_9.0`.

A more detailed and technical account of changes in Vinyl, with
links to issues that have been fixed and pull requests that have been
merged, may be found in the `change log`_.

.. _change log: https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/src/branch/main/doc/changes.rst

vinyld
======

Other changes in vinyld
~~~~~~~~~~~~~~~~~~~~~~~

Varnish Extensions (VEXTs) can now be loaded by specifying their basename as
``-E<name>``. When ``<name>`` is not a path (does not contain ``/``), a search
in ``vmod_path`` is conducted for ``libvmod_<name>.so``.

Receiving ``SIGTERM`` in the management process is no longer logged as an
error, but rather as an INFO log record.

For requests having no request body, the ``Content-Length`` header will now
only be unset when the request method is one of: ``GET``, ``HEAD``, ``DELETE``,
``OPTIONS``, ``TRACE``. For other methods, a ``Content-Length`` header with
value 0 will be set.

A conditional GET for object revalidation is now demoted to a regular fetch if
the stale object being revalidated gets invalidated (e.g. by a ban or purge)
while the backend request is in progress.

Changes to VCL
==============

VCL variables
~~~~~~~~~~~~~

The VCL variable ``beresp.storage_hint`` has been removed.

The ``req.ttl`` variable has been renamed to ``req.max_age`` for clarity.
``req.ttl`` is retained as an alias but is now deprecated and will be removed
in a future version.

A new ``bereq.retry_connect`` variable has been added to control whether Vinyl
will make a second attempt to connect to the backend if a first connection
reuse attempt failed. This can be useful to prevent undesired retries of
potentially non-idempotent requests. Setting to ``false`` means no retries will
be made. This parameter only affects automatic retries triggered by connection
reuse failures and does not affect VCL retries.

Other changes to VCL
~~~~~~~~~~~~~~~~~~~~

A new ``unused`` VCL keyword has been added to mark symbols as intentionally
unused. This prevents errors about unused symbols during VCL compilation and
provides finer grained control compared to the ``-err_unref`` VCC feature,
which disables the error globally for all symbols.

VCL subroutine calls (``VCL_SUB``) are now supported from ``vcl_init`` and
``vcl_fini``.

The ACL's ``+fold`` feature can now be followed with an optional ``(-report)``
to suppress folding-related warnings during VCL compilation.

VMODs
=====

A new ``vmod_math`` has been added, providing mathematical functions.

``vmod_std`` has a new ``.rfc_ttl()`` function to re-calculate the object
timers (``beresp.ttl``, ``beresp.grace`` and ``beresp.keep``) based on the
current state of ``beresp`` as if it had been processed by core code before
``vcl_backend_response`` was called. This does not change
``beresp.uncacheable``.

vinyllog
========

The ``BackendOpen`` VSL tag now also logs connection age and connection reuses
when relevant. These can be useful when troubleshooting idle timeout issues
from the backend.

The response reason when a stale object is not a valid object for refresh has
been made more descriptive to make it easier to differentiate between failure
cases in the logs.

The session close reason descriptions ``REM_CLOSE`` and ``REQ_CLOSE`` have been
generalized from "Client Closed" / "Client requested close" to "Peer Closed" /
"Peer requested close" since they apply to both client and backend connections.

vinylstat
=========

The workspace overflow counters (``ws_backend_overflow``, ``ws_client_overflow``,
``ws_thread_overflow``, ``ws_session_overflow``) are now shown by default
instead of requiring the ``diag`` level.

Changes for developers and VMOD authors
=======================================

``VSL_Setup()`` has been replaced with ``VSL_Init()`` (to initialize
caller-provided space as a VSL buffer) and ``VSL_Alloc()`` (to allocate the
default ``vsl_buffer`` on the heap). ``VSL_Free()`` has been added to free the
memory allocated by ``VSL_Alloc()``. The coccinelle script
``tools/coccinelle/vsl_setup_retire.cocci`` can be used to partially automate
the transition.

Request methods are now represented as a bitmap in ``struct http``, which
allows turning method evaluations into simple bitwise operations instead of
string comparisons.

*eof*
