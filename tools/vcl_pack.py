#!/usr/bin/env python3
#
# Copyright (c) 2026 Varnish Software AS
# SPDX-License-Identifier: BSD-2-Clause
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""
Package a compiled VCL as a single JSON file, and load it back with
vcl.ext_load.

    vcl_pack.py export -n <workdir> [--vmods local|embed] -o <out.json> <vcl>
        Package a VCL loaded in a running varnishd: its symbol table
        comes from "vcl.symtab -j", its vgc.so from the working
        directory.

    vcl_pack.py compile -f <file.vcl> [--vmods local|embed] -o <out.json>
                        [-p param=value]...
        Package a VCL without a running varnishd: "varnishd -C" builds it
        in a throwaway working directory, with the vcl_keep debug flag so
        vgc.so and vgc.sym survive until they are packaged.

    vcl_pack.py load -n <workdir> [-t state] [-T s] [--check-cache]
                     <configname> <in.json>
        Have a running varnishd load a package, using this script as the
        vcl.ext_load program.

    vcl_pack.py <in.json> <dir>
        The vcl.ext_load program contract: write vgc.so and vgc.sym from
        the package into <dir>.

VMODs are not part of a package by default ("--vmods local"): when the
package is loaded, each imported VMOD is looked up at the path recorded
in the symbol table, then in vmod_path, and must have the same file_id
as the one the VCL was compiled against.  A VMOD already in vmod_cache is
used as is, its file_id is only checked with "load --check-cache".  With
"--vmods embed" the VMODs are stored in the package and used from there.
"""

import argparse
import base64
import glob
import hashlib
import json
import os
import subprocess
import sys
import tempfile

FORMAT = "vcl-pack"
VERSION = 1
VMOD_CACHE = "./vmod_cache/"
VMOD_SPEC_MAGIC = b"VMOD_JSON_SPEC\x02"
VMOD_PATH_ENV = "VCL_PACK_VMOD_PATH"
CHECK_CACHE_ENV = "VCL_PACK_CHECK_CACHE"


class PackError(Exception):
    pass


def run(argv, what):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       encoding="utf-8", errors="surrogateescape",
                       check=False)
    if p.returncode != 0:
        raise PackError("%s failed (exit %d):\n%s%s" %
                        (what, p.returncode, p.stdout, p.stderr))
    return p


def check_symtab(symtab):
    return isinstance(symtab, list) and symtab and \
        symtab[0] == {"version": 0}


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(s, what):
    try:
        return base64.b64decode(s, validate=True)
    except (TypeError, ValueError) as e:
        raise PackError("invalid %s: %s" % (what, e))


###############################################################################
# VMODs

def vmod_imports(symtab):
    for e in symtab[1:]:
        if isinstance(e, dict) and e.get("type") == "$VMOD" and \
                not e.get("vext"):
            yield e


def vmod_file_id(e):
    """The file_id the VCL was compiled against, part of dst"""
    pfx = "%s_vmod_%s." % (VMOD_CACHE, e.get("name"))
    dst = e.get("dst", "")
    if not dst.startswith(pfx) or len(dst) == len(pfx):
        raise PackError("unexpected dst for VMOD %s: %r" %
                        (e.get("name"), dst))
    return dst[len(pfx):]


def vmod_spec(data):
    """The $VMOD stanza of the JSON spec, found as libvcc does"""
    i = data.find(VMOD_SPEC_MAGIC)
    if i < 0:
        return None
    i += len(VMOD_SPEC_MAGIC)
    j = data.find(b"\x03", i)
    if j < 0:
        return None
    try:
        spec = json.loads(data[i:j].decode("utf-8"))
        stanza = spec[0]
    except (ValueError, TypeError, IndexError, KeyError):
        return None
    if not isinstance(stanza, list) or len(stanza) < 5 or \
            stanza[0] != "$VMOD":
        return None
    return stanza


def vmod_mismatch(data, e):
    """Why data is not the VMOD e was compiled against, or None"""
    stanza = vmod_spec(data)
    if stanza is None:
        return "no VMOD JSON spec found"
    if stanza[2] != e["name"]:
        return "VMOD name is %r" % stanza[2]
    if stanza[4] != vmod_file_id(e):
        return "file_id is %s" % stanza[4]
    return None


def find_vmod(e, candidates):
    """First candidate that is the VMOD e was compiled against"""
    tried = []
    for path in candidates:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError as err:
            tried.append("%s: %s" % (path, err.strerror))
            continue
        why = vmod_mismatch(data, e)
        if why is None:
            return path, data
        tried.append("%s: %s" % (path, why))
    raise PackError("no VMOD %s with file_id %s:\n\t%s" %
                    (e["name"], vmod_file_id(e), "\n\t".join(tried)))


def embed_vmods(symtab, workdir):
    vmods = {}
    for e in vmod_imports(symtab):
        candidates = [e.get("file", "")]
        if workdir is not None:
            # The copy in vmod_cache is what is actually in use
            candidates.insert(0, os.path.join(workdir, e["dst"]))
        _, data = find_vmod(e, candidates)
        vmods[e["name"]] = {
            "file_id": vmod_file_id(e),
            "sha256": hashlib.sha256(data).hexdigest(),
            "data": b64(data),
        }
    return vmods


###############################################################################
# Package files

def make_pack(args, name, symtab, so, workdir):
    if not check_symtab(symtab):
        raise PackError("Unexpected symbol table format")
    for e in vmod_imports(symtab):
        vmod_file_id(e)
    pack = {
        "format": FORMAT,
        "version": VERSION,
        "name": name,
        "origin": args.cmd,
        "symtab": symtab,
        "so_sha256": hashlib.sha256(so).hexdigest(),
        "so": b64(so),
    }
    if args.vmods == "embed":
        pack["vmods"] = embed_vmods(symtab, workdir)
    return pack


def write_pack(pack, out):
    data = json.dumps(pack, indent=2) + "\n"
    if out == "-":
        sys.stdout.write(data)
        return
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        f.write(data)
    os.replace(tmp, out)


def read_pack(path):
    try:
        with open(path) as f:
            pack = json.load(f)
    except OSError as e:
        raise PackError("Cannot read %s: %s" % (path, e))
    except ValueError as e:
        raise PackError("%s is not a VCL package: %s" % (path, e))
    if not isinstance(pack, dict) or pack.get("format") != FORMAT:
        raise PackError("%s is not a VCL package" % path)
    if pack.get("version") != VERSION:
        raise PackError("%s: unsupported package version %r" %
                        (path, pack.get("version")))
    so = unb64(pack.get("so"), "shared object")
    if hashlib.sha256(so).hexdigest() != pack.get("so_sha256"):
        raise PackError("%s: shared object checksum mismatch" % path)
    if not check_symtab(pack.get("symtab")):
        raise PackError("%s: invalid symbol table" % path)
    vmods = pack.get("vmods", {})
    if not isinstance(vmods, dict):
        raise PackError("%s: invalid vmods" % path)
    for e in vmod_imports(pack["symtab"]):
        vm = vmods.get(e["name"])
        if vm is None:
            continue
        data = unb64(vm.get("data") if isinstance(vm, dict) else None,
                     "VMOD %s" % e["name"])
        if hashlib.sha256(data).hexdigest() != vm.get("sha256"):
            raise PackError("%s: VMOD %s checksum mismatch" %
                            (path, e["name"]))
        why = vmod_mismatch(data, e)
        if why is not None:
            raise PackError("%s: embedded VMOD %s: %s" %
                            (path, e["name"], why))
        vm["bytes"] = data
    return pack, so


###############################################################################
# export: from a running varnishd

def adm_argv(args):
    argv = [args.varnishadm]
    if args.n:
        argv += ["-n", args.n]
    return argv


def adm_json(args, *cmd):
    p = run(adm_argv(args) + list(cmd), " ".join(cmd))
    try:
        return json.loads(p.stdout)[3:]
    except (ValueError, TypeError) as e:
        raise PackError("Cannot parse %s output: %s" % (" ".join(cmd), e))


def cmd_export(args):
    for vcl in adm_json(args, "vcl.symtab", "-j"):
        if vcl.get("name") == args.vcl:
            break
    else:
        raise PackError("No VCL named %s" % args.vcl)
    if vcl.get("label") or vcl.get("symtab") is None:
        raise PackError("%s is a label, not a VCL" % args.vcl)

    workdir = args.workdir
    if workdir is None:
        workdir = run(adm_argv(args) + ["-x", "workdir"],
                      "varnishadm -x workdir").stdout.strip()

    # VCL names cannot contain dots, the glob only matches this VCL
    stamps = {}
    for d in glob.glob(os.path.join(glob.escape(workdir),
                                    "vcl_%s.*.*" % args.vcl)):
        sec, usec = d.rsplit(".", 2)[1:]
        if sec.isdigit() and usec.isdigit() and \
                os.path.isfile(os.path.join(d, "vgc.so")):
            stamps[d] = (int(sec), int(usec))
    if not stamps:
        raise PackError("No vgc.so for %s under %s" % (args.vcl, workdir))

    # vcl_keep can leave older builds behind, the latest is the live one
    with open(os.path.join(max(stamps, key=stamps.get), "vgc.so"),
              "rb") as f:
        so = f.read()

    write_pack(make_pack(args, args.vcl, vcl["symtab"], so, workdir),
               args.o)


###############################################################################
# compile: with varnishd -C, keeping what it built

def cmd_compile(args):
    with tempfile.TemporaryDirectory(prefix="vcl_pack.") as tmp:
        # A jailed compiler may run as another user
        os.chmod(tmp, 0o711)
        workdir = os.path.join(tmp, "n")
        argv = [args.varnishd, "-C", "-n", workdir,
                "-f", os.path.abspath(args.f)]
        for p in args.p:
            argv += ["-p", p]
        argv += ["-p", "debug=+vcl_keep"]
        run(argv, "varnishd -C")

        builds = glob.glob(os.path.join(glob.escape(workdir), "vcl_*"))
        if len(builds) != 1:
            raise PackError("Expected one build in %s, found %d" %
                            (workdir, len(builds)))
        with open(os.path.join(builds[0], "vgc.so"), "rb") as f:
            so = f.read()
        with open(os.path.join(builds[0], "vgc.sym")) as f:
            try:
                symtab = json.load(f)
            except ValueError as e:
                raise PackError("Cannot parse vgc.sym: %s" % e)

        name = os.path.splitext(os.path.basename(args.f))[0]
        pack = make_pack(args, name, symtab, so, None)
    write_pack(pack, args.o)


###############################################################################
# load: hand the package to vcl.ext_load, with this script as program

def cmd_load(args):
    pack = os.path.abspath(args.pack)
    read_pack(pack)
    vmod_path = adm_json(args, "param.show", "-j", "vmod_path")[0]["value"]
    argv = adm_argv(args) + ["vcl.ext_load", args.configname, pack,
                             os.path.abspath(__file__),
                             "-E", "%s=%s" % (VMOD_PATH_ENV, vmod_path)]
    if args.check_cache:
        argv += ["-E", "%s=1" % CHECK_CACHE_ENV]
    if args.t:
        argv += ["-t", args.t]
    if args.T:
        argv += ["-T", str(args.T)]
    return subprocess.run(argv, check=False).returncode


def write_file(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def unpack(pack_path, dst):
    pack, so = read_pack(pack_path)
    symtab = pack["symtab"]
    workdir = os.path.dirname(os.path.abspath(dst))
    vmod_path = [d for d in os.environ.get(VMOD_PATH_ENV, "").split(":")
                 if d]
    check_cache = os.environ.get(CHECK_CACHE_ENV) == "1"

    for e in vmod_imports(symtab):
        cached = os.path.join(workdir, e["dst"])
        if os.path.isfile(cached):
            # Already in vmod_cache, the file is not copied
            if check_cache:
                find_vmod(e, [cached])
            continue
        vm = pack.get("vmods", {}).get(e["name"])
        if vm is not None:
            path = os.path.join(dst, "vmod_%s.so" % e["name"])
            write_file(path, vm["bytes"])
        else:
            lib = "libvmod_%s.so" % e["name"]
            path, _ = find_vmod(e, [e.get("file", "")] +
                               [os.path.join(d, lib) for d in vmod_path])
        e["file"] = os.path.abspath(path)

    # vcl.ext_load created both files empty
    for fn in ("vgc.so", "vgc.sym"):
        os.unlink(os.path.join(dst, fn))
    write_file(os.path.join(dst, "vgc.so"), so)
    write_file(os.path.join(dst, "vgc.sym"), json.dumps(symtab).encode())


###############################################################################

def main(argv):
    cmds = ("export", "compile", "load", "-h", "--help")
    if len(argv) == 2 and argv[0] not in cmds and \
            not argv[0].startswith("-"):
        unpack(argv[0], argv[1])
        return 0

    ap = argparse.ArgumentParser(
        description="Package a compiled VCL as JSON, load it with "
        "vcl.ext_load.")
    ap.add_argument("--varnishd", default="varnishd",
                    help="varnishd binary (default: %(default)s)")
    ap.add_argument("--varnishadm", default="varnishadm",
                    help="varnishadm binary (default: %(default)s)")
    sp = ap.add_subparsers(dest="cmd")
    sp.required = True

    def vmods_arg(p):
        p.add_argument("--vmods", choices=("local", "embed"),
                       default="local",
                       help="use the VMODs of the loading host, or embed "
                       "them in the package (default: %(default)s)")

    p = sp.add_parser("export", help="package a VCL of a running varnishd")
    p.add_argument("-n", help="varnishd working directory (varnishadm -n)")
    p.add_argument("--workdir",
                   help="where the VCL builds live, if not derived from -n")
    vmods_arg(p)
    p.add_argument("-o", required=True, help="output file, - for stdout")
    p.add_argument("vcl", help="name of the VCL to package")
    p.set_defaults(func=cmd_export)

    p = sp.add_parser("compile", help="compile and package a VCL file")
    p.add_argument("-f", required=True, help="VCL file")
    p.add_argument("-p", action="append", default=[],
                   metavar="PARAM=VALUE", help="varnishd -p parameter")
    vmods_arg(p)
    p.add_argument("-o", required=True, help="output file, - for stdout")
    p.set_defaults(func=cmd_compile)

    p = sp.add_parser("load", help="load a package with vcl.ext_load")
    p.add_argument("-n", help="varnishd working directory (varnishadm -n)")
    p.add_argument("-t", choices=("auto", "cold", "warm"),
                   help="initial temperature")
    p.add_argument("-T", type=int, help="vcl.ext_load time limit")
    p.add_argument("--check-cache", action="store_true",
                   help="also check the file_id of VMODs already in "
                   "vmod_cache")
    p.add_argument("configname", help="name of the new VCL")
    p.add_argument("pack", help="package file")
    p.set_defaults(func=cmd_load)

    args = ap.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except PackError as e:
        sys.stderr.write("vcl_pack: %s\n" % e)
        sys.exit(1)
