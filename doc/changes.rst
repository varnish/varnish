* The handling of HTTP/1.1 requests to an "absolute form" URI has been fixed to
  also cover the case where the absolute form has an empty path component:

  Previously, a request with an empty path like ``GET http://example.com
  HTTP/1.1`` would cause ``req.url`` to contain ``http://example.com`` and the
  ``Host:`` header to remain unchanged. This has now been fixed:

  - ``req.url`` gets set to ``*`` if the request method is ``OPTIONS`` and to
    ``/`` otherwise

  - The ``Host:`` header gets set to ``example.com``.

  For an empty path with query parameters like ``http://example.com?/foo``,
  ``req.url`` gets normalized by addition of the leading slash. For the example,
  ``req.url`` would contain ``/?/foo``.

  ([VSV18](https://vinyl-cache.org/security/VSV00018.html))

* `varnishlog-json` has been added to produce structured `JSON` logs.

* TLS is now supported via `varnishd -A FILE` with `FILE` beting the path of a
  `hitch`-like configuration file. It's also possible to use `varnishd -a
  :443,https` and to use `varnishdadm tls.*` to dynamically configure the
  certificates.

* For requests to an absolute form URI, the host field is now required. Requests
  without a host field are rejected with a Status 400 error.

* The built-in VCL has been changed to require ``req.url`` to start with ``/``,
  unless the request method is ``CONNECT`` or ``OPTIONS``. For ``CONNECT``, no
  additional check is applied, but ``CONNECT`` is not allowed by default. For
  ``OPTIONS``, ``*`` is also allowed.

* The ``ReqTarget`` Vinyl Shared Log (VSL) Tag has been added to log the
  original request target before any handling of absolute form URIs. To preserve
  the existing log format and ordering, the tag is marked by default. It can be
  unmasked by adding ``+ReqTarget`` to the ``vsl_mask`` parameter.

* The ``MAIN.http1_absolute_form`` counter has been added to track the number of
  times an HTTP/1.1 request with an absolute form request target has been
  handled.

* The ``https_scheme`` parameter is now enabled by default to process
  ``https://`` absolute form URLs by default.

* The VCL variable ``beresp.storage_hint`` no longer exists.

* The VAI interface gained

  - the ``IOV_NIL`` macro to return leases once delivery has reached a certain
    point,

  - the ``viov_take()`` function to transfer ownership of byte ranges from one
    ``viov`` to another and

  - ``ObjVAInotify()`` / ``VDPIO_Notify()`` to allow filters to return
    ``-EAGAIN`` and notify for delivery resumption at a later point.

* ``VSL_Setup()`` has been replaced with ``VSL_Init()`` to initialize caller-provided
  space as a vsl buffer and ``VSL_Alloc()`` to allocate the default
  ``vsl_buffer`` on the heap.

  ``VSL_Free()`` has been added to free the memory allocated by ``VSL_Alloc()``

  ``tools/coccinelle/vsl_setup_retire.cocci`` can be used to partially automate
  the transition (it does not add ``VSL_Free()``).

* Added vmod ``math``.

* Fixed a bug in VCC where using ``false``/``true`` as a value for ``VCL_BOOL``
  would result in a C-compiler error under certain platforms. ([4452](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4452))

* Request methods are now represented as a bitmap in struct http, which allows
  turning method evaluations as simple bitwise operations instead of string
  comparisons. ([4438](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4438))

* For requests having no request body, Content-length header will now only be
  unset when the request method is one of: ``GET``, ``HEAD``, ``DELETE``,
  ``OPTIONS``, ``TRACE``. Otherwise, a Content-length with value 0 will be set. ([4340](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4340))

* Added vmod ``math``. ([4422](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4422))

  This adds all mathematical functions, macros and constants from ``math.h``
  like ``sqrt()`` , ``exp()``, ``pow()`` or ``log()`` (just to name a few
  prominent ones) as well as

  - ``math.approx()`` implementing a notion of "approximately equal"

  - ``math.strfromd()`` for REAL formatting without the limitations of the
    built-in formatter

* ``vmod_std`` has a new ``.rfc_ttl()`` to re-calculate the object timers
  (``beresp.ttl``, ``beresp.grace`` and ``beresp.keep``) based on the current
  state of ``beresp`` as if it had been processed by core code before
  ``vcl_backend_response`` was called. This does not change
  ``beresp.uncacheable`` ([4427](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4427))

* VEXTs can now be loaded by specifying their basename as `-E<name>`. When <name>
  is not a path (does not contain /), a search in ``vmod_path`` is conducted for
  ``libvmod_<name>.so``. ([4419](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4419))

* The new ``unused`` VCL keyword has been added to mark symbols as intentionally
  unused, which prevents errors about them being unused during VCL compilation.
  This gives finer grained control compared to the ``-err_unref`` VCC feature,
  which disables the error globally for all symbols. ([4421](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4421))

* Improved VCL comparison for probes, backends and ACLs that could lead to C-compiler
  errors in the past. ([4418](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4418))

* Fixed probes comparison in VCC which used to wrongly convert operands to string
  before performing the comparison. ([4417](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/issues/4417))

* Receiving SIGTERM in the management process is no longer logged as an error,
  but rather as an INFO log record. ([4409](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/issues/4409))

* The ``BackendOpen`` VSL tag now also logs Connection age and Connection reuses
  when relevant. These can be useful when trubleshooting idle timeout from the
  backend. ([4007](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4007))

* Fixed a VCC bug where VCL would refuse to compile when a probe was never
  referenced, even when ``'vcc_feature=-err_unref'`` was set. ([4415](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4415))

* A new ``bereq.retry_connect`` variable was added to VCL to control whether
  ``varnishd`` will make a second attempt to connect to the backend if a first
  connection reuse attempt failed. This can be useful to prevent undesired
  retries of potentially non-idempotent requests. Setting this to ``false`` means
  that no retries will be made. However, setting it to ``true`` does not
  guarantee that a retry will always be attempted, as there are other factors
  involved in the decision (e.g. a request body not being cached). This parameter
  only affects automatic retries triggered by connection reuse failures and does
  not affect VCL retries. ([4416](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4416))

* The ACL's ``+fold`` feature can now be followed with an optional ``(-report)``
  to not output folding-related warnings during VCL compilation.

* Fixed a VCC bug where a number expressed in scientific notation could trigger
  an assertion failure.

* Fixed data race between BOC state and objcore flags that could result in a
  panic under certain conditions. ([4402](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/pulls/4402))

* The response reason when the stale object is not a valid object for refresh
  has been made more descriptive to make it easier to differentiate between the
  failure cases in the logs. ([4399](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/issues/4399))

* A conditional GET for object revalidation is now demoted to a regular fetch
  if the stale object being revalidated gets invalidated (e.g. by a ban or
  purge) while the backend request is in progress. This also applies to
  retries. ([4399](https://code.vinyl-cache.org/vinyl-cache/vinyl-cache/issues/4399))

* ``req.ttl`` has been renamed to ``req.max_age`` for clarity, with ``req.ttl``
  being retained as an alias. ``req.ttl`` is now deprecated, but no warning is
  emitted yet. It will be removed in a future version of Varnish-Cache. ([4389](https://github.com/varnishcache/varnish-cache/issues/4389))