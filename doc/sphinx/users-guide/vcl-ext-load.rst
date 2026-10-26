..
	Copyright (c) 2026 Varnish Software AS
	SPDX-License-Identifier: BSD-2-Clause
	See LICENSE file for full text of license

.. _vcl-ext-load:

Loading VCL built by an external compiler
-----------------------------------------

Normally the management process translates VCL to C with the built-in
VCL compiler and builds a shared object with ``cc_command``.  The
``vcl.ext_load`` CLI command replaces this whole pipeline with a
program of your choosing, which must produce the shared object and
its symbol table itself::

    vcl.ext_load <configname> <input> <program> [-t auto|cold|warm] [-T <seconds>] [-E NAME=VALUE]...

``<program>`` must be an absolute path, otherwise the command is
rejected.

``<input>`` is handed to the program verbatim and is not interpreted by
Varnish.  It will typically be a file name, and since the program does
not necessarily run in the same directory as the CLI client, it should
be an absolute path.

``-t`` sets the initial temperature of the VCL, as for ``vcl.load``.
``-T`` sets the time limit for the program, in seconds (default 60).
The test load of the resulting shared object (see below) gets its own,
separate time limit of the same length.
``-E`` adds ``NAME=VALUE`` to the environment of the program, on top of
the environment inherited from the management process, and can be
repeated.

.. warning::

   The program is run with the privileges of the VCL compiler, and any
   user who can authenticate on the CLI can run any program this way.
   Making ``cc_command`` read-only with ``-r cc_command`` does **not**
   prevent this.  See :ref:`run_security`.

The program contract
~~~~~~~~~~~~~~~~~~~~

The program is executed directly, not through a shell, with two
arguments::

    <program> <input> <dir>

where ``<dir>`` is the absolute path of the build directory,
``vcl_<name>.<sec>.<usec>``, under the working directory of Varnish.
That directory is also the current working directory of the program.
The program runs with the same privileges as ``cc_command`` (including
the ``cc_group`` group, where applicable), with a umask of 027.

The output of the program is relayed to the CLI client, up to 1 MiB;
anything beyond that is discarded and an ``[output truncated]`` note
is added.  (The ``cli_limit`` parameter may truncate the response
further.)  The program runs in a process group of its own.  If it has
not exited after the ``-T`` timeout, the process group and the program
itself are killed with ``SIGKILL`` and the load fails.  This also
applies when the program closed its output early or left its process
group.  Descendants that left the process group are not killed, but
Varnish does not wait for them either.

On success the program must exit with status 0, having left two files
in ``<dir>``:

``vgc.so``
	A shared object compatible with the VRT ABI of the running Varnish,
	exporting ``VCL_conf``.

``vgc.sym``
	The symbol table, in the JSON format also written by the VCL
	compiler: an array whose first element is ``{"version": 0}``,
	followed by one entry per import.

For a ``$VMOD`` import the entry has a ``name`` and a boolean ``vext``.
When ``vext`` is false, it also needs ``file``, the VMOD to use, and
``dst``, where it is expected at run time.  ``dst`` must have the form
``./vmod_cache/<name>`` with a single path component, relative to the
working directory of Varnish.  The management process copies the VMOD
from ``file`` to ``dst``, unless ``dst`` already exists as a regular
file.  ``file`` may be a symbolic link, but must lead to a regular
file.  A ``$VCL`` import may only refer to labels of existing VCLs.
``vgc.sym`` must be a regular file (not a symbolic link) of at most
64 MiB, with arrays and objects nested at most 64 levels deep.  A
symbol table that does not meet these rules is rejected with an
``Invalid symbol table: ...`` message and the load fails.

Once the program has exited successfully, Varnish first checks that
``vgc.so`` is a regular file (not a symbolic link) and performs the
usual test load of it, in a separate process bounded by the ``-T``
timeout.  Only then is ``vgc.sym`` read and validated, and the VMODs it
lists copied.

If everything succeeds, only ``vgc.so`` is kept and everything else in
``<dir>`` is removed (recursively, without following symbolic links).
If anything fails, the whole directory is removed.  With the
``vcl_keep`` debug flag nothing is removed.

The result is an ordinary VCL: it shows up in ``vcl.list`` and can be
used, labelled, and discarded like any other.  It survives restarts of
the child process without running the program again.

Example
~~~~~~~

A stand-in "compiler" that only installs a previously built shared object
and symbol table::

    #!/bin/sh
    # $1 is the <input>, here a directory with prebuilt artifacts
    # $2 is the build directory, also the current directory
    set -e
    cp "$1/vgc.so" "$1/vgc.sym" "$2"

Used as::

    vcl.ext_load mycfg /srv/prebuilt/mycfg /usr/local/bin/ext-cc.sh -T 120 -E MODE=prod

A real compiler would replace the ``cp`` with the translation of
``<input>`` to a shared object, writing ``vgc.sym`` along the way.

Packaging compiled VCL
~~~~~~~~~~~~~~~~~~~~~~

``tools/vcl_pack.py`` in the source tree packs a compiled VCL into a
single JSON file holding ``vgc.so`` and its symbol table, and acts as a
``vcl.ext_load`` program that unpacks such a file.  A package is made
either from a VCL loaded in a running ``varnishd``, or from a VCL file
with ``varnishd -C``, run in a throwaway working directory with the
``vcl_keep`` debug flag::

    vcl_pack.py export -n /var/lib/varnish/varnishd -o boot.json boot
    vcl_pack.py compile -f /etc/varnish/default.vcl -o default.json

and loaded with::

    vcl_pack.py load -n /var/lib/varnish/varnishd mycfg default.json

which runs ``vcl.ext_load mycfg <default.json> <vcl_pack.py>``, both
paths made absolute.

By default (``--vmods local``) the package does not contain the VMODs.
When it is loaded, each VMOD import is looked up at its ``file`` in the
symbol table, then in ``vmod_path``, and the first one with the
``file_id`` the VCL was compiled against is used.  A VMOD already
present in ``vmod_cache`` is used as is, and its ``file_id`` is only
checked when ``load`` is given ``--check-cache``.  With ``--vmods
embed`` the VMODs are stored in the package and used from there.
