**Note: This is a working document for a future release, with running
updates for changes in the development branch. For changes in the
released versions of Varnish, see:** :ref:`whats-new-index`

.. _whatsnew_upgrading_CURRENT:

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Upgrading to Varnish **$NEXT_RELEASE**
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

IPv4 addresses in IPv6 and ACLs
================================

IPv4 compatible and IPv4 mapped IPv6 addresses, that is IPv6 addresses in the
forms ``::<IP4>`` and ``::ffff:<IP4>``, now get rewritten to IPv4 addresses.

For example, with Varnish up to and including 9.0, an IPv6 peer address
``::ffff:176.58.90.154`` would confusingly be logged as ``176.58.90.154``, but
would not match an ACL allowing ``176.58.90.154``.

This has changed now: what looks like IPv4 gets rewritten to IPv4, such that,
for the example above, an ACL allowing ``176.58.90.154`` would match, while an
ACL allowing ``::ffff:176.58.90.154`` would no longer match.

VCL: ``synthetic()`` removed
============================

The ``synthetic()`` VCL action has been removed. Since Varnish Cache 5.0.0, body
data can be created by setting ``beresp.body`` in ``vcl_backend_error {}`` and
by setting ``resp.body`` in ``vcl_synth {}``, and these continue to be available
as the one way to create body data, as in these examples:

- ``set resp.body = "string" + " more strings";``
- ``set resp.body += " appending even " + "more strings";``
- ``set resp.body = :blob:;``
- ``set resp.body += :blobappend:;``

These examples equally work on ``beresp.body`` in ``vcl_backend_error {}``.

The direct replacement for ``synthetic(<string>);`` is ``set resp.body +=
<string>;`` in ``vcl_synth {}`` and ``set beresp.body += <string>;`` in
``vcl_backend_error {}``.

The only difference in behavior is that ``synthetic(<nullstring>)`` would create
the string ``(null)`` for ``<nullstring>`` being a ``NULL`` pointer internally,
while ``set resp.body = <nullstring>`` creates the empty string ``""`` and ``set
resp.body += <nullstring>`` is a NOOP.

VCL variables changed
======================

Setting ``req.max_age = 0s`` now forces a cache miss with request coalescing,
where it previously had no effect.

Breaking changes for VMOD authors
==================================

The ``LBODY_SET`` and ``LBODY_ADD`` compatibility defines have been removed from
``vrt.h``. ``LBODY_{SET,ADD}_{BLOB,STRING}`` should be used instead.

The functions ``VRT_synth_strands()``, ``VRT_synth_blob()``,
``VRT_synth_page()`` and ``VRT_Stv()`` have been removed from the runtime.
``VRT_l_resp_body()`` and ``VRT_l_beresp_body()`` should be used instead.

The ``struct VCL_conf`` and ``struct VSC_main`` declarations have been removed
from ``vrt.h``. ``struct vmod_data`` has moved to ``vmod_abi.h``. Neither of
these should have been used by VMODs.

The VDP API has been changed: After a non-zero return of ``.init()``,
``.fini()`` is no longer called. This might require adjustments of ``.init()``
to add cleanup for error returns.

``cache/cache_varnishd.h`` has been renamed to ``cache/cache_int.h``. You should
avoid using it and try to stick to the API (``vrt.h`` and ``cache.h`` if
needed).

*eof*
