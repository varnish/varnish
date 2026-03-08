..
	Copyright (c) 2010-2016 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license

.. role:: ref(emphasis)

.. _vinylhist(1):

===========
varnishhist
===========

-------------------------
Varnish request histogram
-------------------------

:Manual section: 1

SYNOPSIS
========

.. include:: ../include/vinylhist_synopsis.rst
varnishhist |synopsis|

DESCRIPTION
===========

The varnishhist utility reads vinyld(1) shared memory logs and
presents a continuously updated histogram showing the distribution
of the last N requests by their processing.  The value of N and the
vertical scale are displayed in the top left corner.  The horizontal
scale is logarithmic.  Hits are marked with a pipe character ("|"),
and misses are marked with a hash character ("#").

The following options are available:

.. include:: ../include/vinylhist_options.rst

SEE ALSO
========

* :ref:`vinyld(1)`
* :ref:`vinyllog(1)`
* :ref:`vinylncsa(1)`
* :ref:`vinylstat(1)`
* :ref:`vinyltop(1)`
* :ref:`vsl(7)`

HISTORY
=======
The varnishhist utility was developed by Poul-Henning Kamp in cooperation with
Verdens Gang AS and Varnish Software AS. This manual page was written by
Dag-Erling Smørgrav.

COPYRIGHT
=========

This document is licensed under the same licence as Varnish
itself. See LICENCE for details.

* Copyright (c) 2006 Verdens Gang AS
* Copyright (c) 2006-2015 Varnish Software AS
