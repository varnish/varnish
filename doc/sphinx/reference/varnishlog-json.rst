..
	Copyright (c) 2024,2026 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license

.. role:: ref(emphasis)

.. _varnishlog-json(1):

===============
varnishlog-json
===============

----------------------------
Display Varnish logs in JSON
----------------------------

:Manual section: 1

SYNOPSIS
========

.. include:: ../include/varnishlog-json_synopsis.rst
varnishlog-json |synopsis|

DESCRIPTION
===========

The ``varnishlog-json`` utility reads and presents Varnish logs in JSON
format. It can output newline-delimited JSON (NDJSON) or pretty-printed
JSON.

Transactions are represented as seen by the remote party (client or
backend). For backend transactions, any modifications to the backend
request that happen after transmission are not shown. For client
transactions, modifications to the request made by VCL before the
response is delivered are not shown.

ESI and backend transactions are excluded by default, matching
``varnishlog`` behavior.

The following grouping modes are available with the ``-g`` option:

* ``vxid`` - Group by VXID (default). Each transaction is output as a
  single JSON object.

* ``request`` - Group by request. Related transactions (e.g. a client
  request and its backend fetches) are output as a JSON array.

* ``probe`` - Display backend health probe results. Internally uses
  raw grouping to collect probe data into structured JSON objects.

OPTIONS
=======

The following options are available:

.. include:: ../include/varnishlog-json_options.rst

JSON STRUCTURE
==============

``varnishlog-json`` gets its data from the same source as ``varnishlog``, so
it's important to understand which tags are used to produce the output. It can
be particularly useful if you want to suppress part of the object using the
``-i/-I/-x/-X`` arguments.

We'll use ``typescript`` notation to describe the object shape:

::

  {
      req: {                                      // describes the request as seen by the remote (either client, or backend)
          headers: Map<string, string>,           // keys (header names) are lowercase, this map is built using ReqHeader,
                                                  // BereqHeader, RespUnset, and BerespUnset tags
          method: string,                         // ReqMethod, BereqMethod
          proto: string,                          // ReqProtocol, BereqProtocol
          hdrBytes: number,                       // ReqAcct, BereqAcct
          bodyBytes: number,                      // ^ same
      },
      resp: {                                     // describes the remote as seen by the remote
          headers: Map<string, string>,           // keys (header names) are lowercase, uses ReqHeader,
                                                  //   BereqHeader, RespUnset, and BerespUnset
          set-cookie?: Array<string>,             // Set-Cookie headers
          proto: string,                          // RespProtocol, BerespProtocol
          status: number,                         // RespStatus, BerespStatus
          reason: string,                         // RespReason, BerespReason,
          hdrBytes: number,                       // ReqAcct, BereqAcct
          bodyBytes: number,                      // ^ same
      },
      handling: "hit" | "miss" | "pass" |"pipe" |
                "streaming-hit" | "fail" | "synth"
                "abandon" | "fetch" | "error",    // how the request was handled, using VCL_call records, notably
      timeline: Array<{name: string,
                       timestamp: number}>        // Timestamp records
      side: "backend" | "client",
      id: string,                                 // the transaction's vxid
      vcl: string                                 // VCL_use
      client?: {                                  // ReqStar (client-side only)
          rAddr: string,
          rPort: number,
          sock: string,
      },
      backend?: {                                 // BackendOpen (backend-side only)
          name: string,                           // the name is simplified to the director name for udo/goto backends
          rAddr: string,
          rPort: number,
          connReused: bool,
      },
      storage?: string,                           // Storage (backend-only)
      errors?: Array<string>,                     // Error, VCL_Error, FetchError, if the VSL transaction was incomplete
      logs: Array<string>,                        // VCL_Log
      links: Array<{                              // Link
          type: string,
          id: string,
          reason: string,
      }>,
  }

If you use ``-g request``, instead of one object per line, ``varnishlog-json``
will output an array of all objects in the group.

SIGNALS
=======

* SIGHUP

  Rotate the log file (see -w option) in daemon mode,
  abort the loop and die gracefully when running in the foreground.

* SIGUSR1

  Flush any outstanding transactions

OUTPUT
======

By default ``varnishlog-json`` outputs one JSON object per line in
NDJSON format. Each JSON object represents a transaction and contains
request/response details, handling classification, timeline events,
transaction IDs, and VCL information.

When using ``-g request``, related transactions are grouped into JSON
arrays.

When using ``-p``, output is pretty-printed with indentation for
readability.

EXAMPLES
========

Display client transactions in real time::

	varnishlog-json

Display backend transactions with pretty-printing::

	varnishlog-json -b -p

Log client requests to a file in daemon mode::

	varnishlog-json -D -w /var/log/varnish/json.log -P /run/varnishlog-json.pid

Filter requests for a specific URL::

	varnishlog-json -q 'ReqURL eq "/api/health"'

Display request groups (client + related backend transactions)::

	varnishlog-json -g request

Display backend health probe results::

	varnishlog-json -g probe

Read from a binary log file::

	varnishlog-json -r /var/log/varnish/raw.log

SEE ALSO
========

* :ref:`varnishd(1)`
* :ref:`varnishlog(1)`
* :ref:`vsl(7)`
* :ref:`vsl-query(7)`

COPYRIGHT
=========

This document is licensed under the same licence as Varnish
itself. See LICENCE for details.

* Copyright (c) 2024,2026 Varnish Software AS
