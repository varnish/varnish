..
	Copyright (c) 2010-2015 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license


.. _glossary:

Vinyl Cache Glossary
====================

.. glossary::
   :sorted:

   ..
	This file will be sorted automagically during formatting,
	so we keep the source in subject order to make sure we
	cover all bases.

   .. comment: "components of Vinyl Cache --------------------------------"

   vinyld (NB: with 'd')
	This is the main Vinyl Cache program.  There is only
	one program, but when you run it, you will get *two*
	processes:  The "master" and the "worker" (or "child").

   master (process)
	One of the two processes in the vinyld program.
	The master process is a manager/nanny process which handles
	configuration, parameters, compilation of :term:VCL etc.
	but it does never get near the actual HTTP traffic.

   worker (process)
	The worker process is started and configured by the master
	process.  This is the process that does all the work you actually
	want vinyld to do.  If the worker dies, the master will try start
	it again, to keep your website alive.

   backend
	The HTTP server vinyld is caching for.  This can be
	any sort of device that handles HTTP requests, including, but
	not limited to: a webserver, a CMS, a load-balancer
	another vinyld, etc.

   client
	The program which sends vinyld an HTTP request, typically
	a browser, but do not forget to think about spiders, robots
	script-kiddies and criminals.

   vinylstat
	Program which presents Vinyl Cache statistics counters.

   vinyllog
	Program which presents Vinyl Cache transaction log in native format.

   vinyltop
	Program which gives real-time "top-X" list view of transaction log.

   vinylncsa
	Program which presents Vinyl Cache transaction log in "NCSA" format.

   vinylhist
	Eye-candy program showing response time histogram in 1980s
	ASCII-art style.

   vinyltest
	Program to test vinyld's behaviour with, simulates backend
	and client according to test-scripts.

   .. comment: "components of traffic ---------------------------------"

   header
	An HTTP protocol header, like "Accept-Encoding:".

   request
	What the client sends to vinyld and vinyld sends to the backend.

   response
	What the backend returns to vinyld and vinyld returns to
	the client.  When the response is stored in vinyld's cache,
	we call it an object.

   backend response
        The response specifically served from a backend to
        vinyld. The backend response may be manipulated in
        vcl_backend_response.

   body
	The bytes that make up the contents of the object, vinyld
	does not care if they are in HTML, XML, JPEG or even EBCDIC,
	to vinyld they are just bytes.

   object
	The (possibly) cached version of a backend response. vinyld
	receives a response from the backend and creates an object,
	from which it may deliver cached responses to clients. If the
	object is created as a result of a request which is passed, it
	will not be stored for caching.

   .. comment: "configuration of vinyld -----------------------------"

   VCL
	Vinyl Configuration Language, a small specialized language
	for instructing vinyld how to behave.

   .. comment: "actions in VCL ----------------------------------------"

   hit
	An object vinyld delivers from cache.

   miss
	An object vinyld fetches from the backend before it is served
	to the client.  The object may or may not be put in the cache,
	that depends.

   pass
	An object vinyld does not try to cache, but simply fetches
	from the backend and hands to the client.

   pipe
	vinyld just moves the bytes between client and backend, it
	does not try to understand what they mean.

