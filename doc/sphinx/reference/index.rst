..
	Copyright (c) 2010-2021 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license

.. _reference-index:

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
The Vinyl Cache Reference Manual
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

.. _reference-vcl:

The VCL language
----------------

.. toctree::
	:maxdepth: 1

	VCL - The Vinyl Configuration Language <vcl>
	VCL Variables <vcl-var>
	VCL Steps <vcl-step>
	VCL backend configuration <vcl-backend>
	VCL backend health probe <vcl-probe>
	states.rst

A collection of :ref:`vcl-design-patterns-index` is available in addition to
these reference manuals.

Bundled VMODs
-------------

.. toctree::
	:maxdepth: 1

	vmod_blob.rst
	vmod_cookie.rst
	vmod_directors.rst
	vmod_h2.rst
	vmod_math.rst
	vmod_proxy.rst
	vmod_purge.rst
	vmod_std.rst
	vmod_unix.rst

The CLI interface
-----------------

.. toctree::
	:maxdepth: 1

	VinylAdm - Control program for Vinyl Cache <vinyladm>
	CLI - The commands Vinyl Cache understands <vinyl-cli>

Logging and monitoring
----------------------

.. toctree::
	:maxdepth: 1

	VSL - The log records Vinyl Cache generates <vsl>
	VSLQ - Filter/Query expressions for VSL <vsl-query>
	VarnishLog - Logging raw VSL <varnishlog>
	VinylLog - Logging raw VSL <vinyllog>
	VarnishLog-JSON - Logging in JSON format <varnishlog-json>
	VinylNCSA - Logging in NCSA format <vinylncsa>
	VinylHist - Realtime response histogram display <vinylhist>
	VinylTop - Realtime activity display <vinyltop>

Counters and statistics
-----------------------

.. toctree::
	:maxdepth: 1

	VSC - The statistics Vinyl Cache collects <vinyl-counters>
	VinylStat - Watching and logging statistics <vinylstat>

The Vinyld program
------------------

.. toctree::
	:maxdepth: 1

	VinylD - The program which does the actual work <vinyld>

Vinyltest
---------

.. toctree::
	:maxdepth: 1

	VTC - Language for writing test cases <vtc>
	VinylTest - execute test cases <vinyltest>
	vmod_vtc.rst

For Developers & DevOps
-----------------------

.. toctree::
	:maxdepth: 1

	Shell tricks <shell_tricks>
	VMODS - Extensions to VCL <vmod>
	VEXT - Vinyl Cache Extensions <vext>
	VSM - Shared memory use <vsm>
	VDIR - Backends & Directors <directors>
	VCLI - CLI protocol API <cli_protocol>

.. Vmod_debug ?

.. Libvinylapi

.. VRT

.. VRT compat levels

Code-book
---------

.. toctree::
	:maxdepth: 1

	vtla.rst
