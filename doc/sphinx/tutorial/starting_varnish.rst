..
	Copyright (c) 2010-2015 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license

.. _tutorial-starting_vinyl:


Starting Vinyl Cache
--------------------

This tutorial will assume that you are running Vinyl Cache on Ubuntu, Debian,
Red Hat Enterprise Linux or CentOS. Those of you running on other
platforms might have to do some mental translation exercises in order
to follow this. Since you're on a "weird" platform you're probably used
to it. :-)

Make sure you have Vinyl Cache successfully installed (following one of the
procedures described in "Installing Vinyl Cache" above.

When properly installed you start Vinyl Cache with ``service vinyl start``.  This
will start Vinyl Cache if it isn't already running.

.. XXX:What does it do if it is already running? benc

Now you have Vinyl Cache running. Let us make sure that it works
properly. Use your browser to go to http://127.0.0.1:6081/ (Replace the IP
address with the IP for the machine that runs Vinyl Cache) The default
configuration will try to forward requests to a web application running on the
same machine as Vinyl Cache was installed on. Vinyl Cache expects the web application
to be exposed over http on port 8080.

If there is no web application being served up on that location Vinyl Cache will
issue an error. Vinyl Cache is very conservative about telling the
world what is wrong so whenever something is amiss it will issue the
same generic "Error 503 Service Unavailable".

You might have a web application running on some other port or some
other machine. Let's edit the configuration and make it point to
something that actually works.

Fire up your favorite editor and edit `/etc/vinyl/default.vcl`. Most
of it is commented out but there is some text that is not. It will
probably look like this::

  vcl 4.0;

  backend default {
      .host = "127.0.0.1";
      .port = "8080";
  }

We'll change it and make it point to something that works. Hopefully
http://www.vinyl-cache.org/ is up. Let's use that. Replace the text with::

  vcl 4.0;

  backend default {
      .host = "www.vinyl-cache.org";
      .port = "80";
  }


Now issue ``service vinyl reload`` to make Vinyl Cache reload it's
configuration. If that succeeded visit http://127.0.0.1:6081/ in your
browser and you should see some directory listing. It works! The
reason you're not seeing the Vinyl Cache official website is because your
client isn't sending the appropriate `Host` header in the request and
it ends up showing a listing of the default webfolder on the machine
usually serving up http://www.vinyl-cache.org/ .
