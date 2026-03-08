..
	Copyright (c) 2010-2015 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license

.. _tutorial-backend_servers:

Backend servers
---------------

Vinyl Cache has a concept of `backend` or origin servers. A backend
server is the server providing the content Vinyl Cache will accelerate via the cache.

Our first task is to tell Vinyl Cache where it can find its content. Start
your favorite text editor and open the Vinyl Cache default configuration
file. If you installed from source this is
`/usr/local/etc/vinyl/default.vcl`, if you installed from a package it
is probably `/etc/vinyl/default.vcl`.

If you've been following the tutorial there is probably a section of
the configuration that looks like this::

  vcl 4.0;

  backend default {
      .host = "www.vinyl-cache.org";
      .port = "80";
  }

This means we set up a backend in Vinyl Cache that fetches content from
the host www.vinyl-cache.org on port 80.

Since you probably don't want to be mirroring vinyl-cache.org we
need to get Vinyl Cache to fetch content from your own origin
server. We've already bound Vinyl Cache to the public port 80 on the
server so now we need to tie it to the origin.

For this example, let's pretend the origin server is running on
localhost, port 8080.::

  vcl 4.0;

  backend default {
    .host = "127.0.0.1";
    .port = "8080";
  }


Vinyl Cache can have several backends defined and can even join several backends
together into clusters of backends for load balancing purposes, having Vinyl Cache
pick one backend based on different algorithms.

Next, let's have a look at some of what makes Vinyl Cache unique and what you can do with it.


