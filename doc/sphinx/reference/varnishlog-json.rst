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

varnishlog-json [-a] [-b] [-c] [-C] [-d] [-D] [-E] [-g <probe|request|vxid>] [-h] [-i <taglist>] [-I <[taglist:]regex>] [-k <num>] [-L <limit>] [-n <workdir>] [-p] [-P <file>] [-Q <file>] [-q <query>] [-r <filename>] [-R <limit[/duration]>] [-t <seconds|off>] [-T <seconds>] [-V] [-w <filename>] [-x <taglist>] [-X <[taglist:]regex>] [--optstring]

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

-a

	When writing output to a file with the -w option, append to it
	rather than overwrite it. This option has no effect without the
	-w option.

-b

	Only display transactions and log records coming from backend
	communication.

-c

	Only display transactions and log records coming from client
	communication.

-C

	Do all regular expression and string matching caseless.

-d

	Process log records at the head of the log and exit.

-D

	Daemonize.

-E

	Display ESI transactions and other types of sub-requests. This
	implies the -c option and includes other client transactions.

-g <probe|request|vxid>

	The grouping of transactions. The default is to group by
	vxid.

	In ``vxid`` mode, each transaction is output as an individual
	JSON object.

	In ``request`` mode, related transactions are grouped and output
	as a JSON array.

	In ``probe`` mode, backend health probe results are collected
	and output as structured JSON objects.

-h

	Print program usage and exit.

-i <taglist>

	Include log records of these tags in output. Taglist is a
	comma-separated list of tag globs. Multiple -i options may be
	given.

	If a tag include option is the first of any tag selection
	options, all tags are first marked excluded.

-I <[taglist:]regex>

	Include by regex matching. Output only records matching taglist
	and regular expression. Applies to any tag if taglist is absent.
	Multiple -I options may be given.

	If a tag include option is the first of any tag selection
	options, all tags are first marked excluded.

-k <num>

	Process this number of matching log transactions before exiting.

-L <limit>

	Sets the upper limit of incomplete transactions kept before the
	oldest transaction is force completed. A warning record is
	synthesized when this happens. This setting keeps an upper bound
	on the memory usage of running queries. Defaults to 1000
	transactions.

-n <workdir>

	Specify the varnish working directory of the instance to attach
	to. See :ref:`varnishd(1)` ``-n`` option documentation for
	additional information and defaults.

-p

	Pretty-print transactions rather than using NDJSON.

-P <file>

	Write the process' PID to the specified file.

-Q <file>

	Specifies the file containing the VSL query to use. When
	multiple -Q or -q options are specified, all queries are
	considered as if the 'or' operator was used to combine them.

-q <query>

	Specifies the VSL query to use. When multiple -q or -Q options
	are specified, all queries are considered as if the 'or'
	operator was used to combine them.

-r <filename>

	Read log in binary file format from this file. The file can be
	created with ``varnishlog -w filename``. If the filename is -,
	logs are read from the standard input and cannot work as a
	daemon.

-R <limit[/duration]>

	Restrict the output to the specified limit. Transactions
	exceeding the limit will be suppressed. The limit is specified
	as the maximum number of transactions (with respect to the
	chosen grouping method) and an optional time period. If no
	duration is specified, a default of ``s`` is used. The duration
	field can be formatted as in VCL (e.g. ``-R 10/2m``) or as a
	simple time period without the prefix (e.g. ``-R 5/m``).

-t <seconds|off>

	Timeout before returning error on initial VSM connection. If set
	the VSM connection is retried every 0.5 seconds for this many
	seconds. If zero the connection is attempted only once and will
	fail immediately if unsuccessful. If set to "off", the
	connection will not fail, allowing the utility to start and wait
	indefinitely for the Varnish instance to appear. Defaults to 5
	seconds.

-T <seconds>

	Sets the transaction timeout in seconds. This defines the
	maximum number of seconds elapsed between a Begin tag and the
	End tag. If the timeout expires, a warning record is synthesized
	and the transaction is force completed. Defaults to 120 seconds.

-V

	Print version information and exit.

-w <filename>

	Redirect output to file. The file will be overwritten unless the
	-a option was specified. If the application receives a SIGHUP in
	daemon mode the file will be reopened allowing the old one to be
	rotated away. This option is required when running in daemon
	mode. If the filename is -, varnishlog-json writes to the
	standard output and cannot work as a daemon.

-x <taglist>

	Exclude log records of these tags in output. Taglist is a
	comma-separated list of tag globs. Multiple -x options may be
	given.

-X <[taglist:]regex>

	Exclude by regex matching. Do not output records matching
	taglist and regular expression. Applies to any tag if taglist is
	absent. Multiple -X options may be given.

--optstring
	Print the optstring parameter to ``getopt(3)`` to help writing
	wrapper scripts.

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
