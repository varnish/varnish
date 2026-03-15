.. _whatsnew_upgrading_9.0:

%%%%%%%%%%%%%%%%%%%%%%%%%%%%
Upgrading to Varnish Cache 9.0
%%%%%%%%%%%%%%%%%%%%%%%%%%%%

This document only lists breaking changes that you should be aware of when
upgrading from Varnish Cache 8.x to Varnish Cache 9.0. For a complete list of
changes, please refer to the `change log`_ and :ref:`whatsnew_changes_9.0`.

.. _change log: https://github.com/varnish/varnish/blob/main/doc/changes.rst

varnishd
======

VCL variable ``beresp.storage_hint`` removed
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The VCL variable ``beresp.storage_hint`` has been removed. If you were using
this variable in your VCL, you will need to remove any references to it.

VCL variable ``req.ttl`` deprecated
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``req.ttl`` variable has been renamed to ``req.max_age`` for clarity.
``req.ttl`` is retained as an alias and continues to work, but is now deprecated
and will be removed in a future version of Varnish Cache. You should update your
VCL to use ``req.max_age`` instead.

Content-Length handling for requests without body
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

For requests having no request body, the ``Content-Length`` header will now
only be unset when the request method is one of: ``GET``, ``HEAD``, ``DELETE``,
``OPTIONS``, ``TRACE``. For other methods, a ``Content-Length`` header with
value 0 will be set instead. This may affect backends that are sensitive to
the presence of the ``Content-Length`` header.

Upgrade notes for VMOD developers
=================================

``VSL_Setup()`` replaced with ``VSL_Init()`` and ``VSL_Alloc()``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``VSL_Setup()`` has been replaced with two new functions:

- ``VSL_Init()`` to initialize caller-provided space as a VSL buffer
- ``VSL_Alloc()`` to allocate the default ``vsl_buffer`` on the heap

``VSL_Free()`` has been added to free the memory allocated by ``VSL_Alloc()``.

The coccinelle script ``tools/coccinelle/vsl_setup_retire.cocci`` can be used
to partially automate the transition (it does not add ``VSL_Free()`` calls).

*eof*
