# AGENTS.md — Varnish Codebase Guide

## Project overview

This repo is the **Varnish** project by Varnish Software AS — an HTTP reverse proxy and
caching daemon, downstream of the **vinyl** open-source project. Most binaries and source
directories use the `vinyl` prefix because they originate from that upstream. Concepts and
acronyms (VCL, VSL, VSM, VSC, VCC) retain their original "Varnish" names.

**`varnishlog-json`** is currently the only downstream-only binary — not from vinyl
upstream. All other `vinyl*` binaries come from upstream. When changing code:
- `vinyl*` tool changes may need upstreaming to vinyl
- `varnishlog-json` changes are downstream-only, and it builds via CMake, not autotools —
  see [bin/varnishlog-json/AGENTS.md](bin/varnishlog-json/AGENTS.md)

Language: C99. Build: autoconf/automake (see "Build & dependencies" below). License: BSD 2-clause.

This file covers project-wide concepts and conventions. Subsystem-specific detail lives in
per-directory `AGENTS.md` files — see the table of contents below.

---

## Repository layout

```
bin/
  vinyld/          main daemon; subdivided into: acceptor/ cache/ common/ hash/ hpack/
                   http1/ http2/ mgt/ proxy/ storage/ tls/ waiter/ fuzzers/
                   — see bin/vinyld/AGENTS.md
  vinyladm/        CLI administration tool
  vinylhist/       histogram log viewer
  vinyllog/        log streaming (VSL reader)
  vinylncsa/       Apache NCSA-format log output
  vinylstat/       statistics viewer (curses)
  vinyltop/        top-like statistics viewer
  vinyltest/       VTC test runner (binary: varnishtest, aliased as vtest)
                   — see bin/vinyltest/AGENTS.md
  varnishlog-json/ JSON-format VSL output (downstream-only, CMake build)
                   — see bin/varnishlog-json/AGENTS.md

lib/
  libvcc/          VCL compiler — see lib/libvcc/AGENTS.md
  libvinyl/        utility library: vsb, vjsn, vre, vss, vfil, vtim, vnum, ...
                   (historically "libvarnish" upstream) — see lib/libvinyl/AGENTS.md
  libvinylapi/     public API: VSL, VSM, VSC client implementations
                   (historically "libvarnishapi" upstream) — see lib/libvinylapi/AGENTS.md
  libvgz/          gzip support (vendored zlib wrapper, kept in sync with upstream — don't
                   hand-modify casually)
  libvsc/          .vsc counter definition files (VSC_main.vsc, VSC_lck.vsc, ...)

include/           public headers
  tbl/             X-macro table files (46 headers) — see include/tbl/AGENTS.md
  vapi/            public API headers (vsm.h, vsl.h, vsl_int.h, vsc.h)
  compat/          platform compatibility shims (e.g. daemon.h)

vmod/              built-in VMODs (blob, cookie, debug, directors, h2, math,
                   proxy, purge, std, tls, unix, vtc) — see vmod/AGENTS.md

doc/sphinx/        Sphinx RST documentation
  users-guide/     operator documentation
  reference/       technical reference (VCL, VMODs, tools)
  dev-guide/       developer guide (see policy_vmods.rst, referenced from vmod/AGENTS.md)
  glossary/, installation/, tutorial/, vcl-design-patterns/, whats-new/, _static/

etc/               builtin.vcl, example.vcl, TLS test certificates
tools/             dev utilities: vtc-bisect.sh, vtest.sh, coverity-run, coccinelle/, flint.lnt
```

### Table of contents — per-directory AGENTS.md files

| Directory | Covers |
|---|---|
| [bin/vinyld/AGENTS.md](bin/vinyld/AGENTS.md) | Daemon process split, subdir map |
| [bin/vinyld/cache/AGENTS.md](bin/vinyld/cache/AGENTS.md) | Core structs, request FSM, filters, ban system, workspace |
| [bin/vinyld/http2/AGENTS.md](bin/vinyld/http2/AGENTS.md) | HTTP/2 protocol layer |
| [bin/vinyld/tls/AGENTS.md](bin/vinyld/tls/AGENTS.md) | TLS layer |
| [bin/vinyld/storage/AGENTS.md](bin/vinyld/storage/AGENTS.md) | Stevedore storage backends |
| [bin/vinyltest/AGENTS.md](bin/vinyltest/AGENTS.md) | VTC testing DSL, running tests |
| [bin/varnishlog-json/AGENTS.md](bin/varnishlog-json/AGENTS.md) | Downstream-only binary, CMake build |
| [lib/libvcc/AGENTS.md](lib/libvcc/AGENTS.md) | VCL language, VCC compiler |
| [lib/libvinylapi/AGENTS.md](lib/libvinylapi/AGENTS.md) | VSL, VSM, VSC |
| [lib/libvinyl/AGENTS.md](lib/libvinyl/AGENTS.md) | vsb, txt, utility functions |
| [vmod/AGENTS.md](vmod/AGENTS.md) | Writing VMODs, vrt_ctx |
| [include/tbl/AGENTS.md](include/tbl/AGENTS.md) | X-macro table pattern |

---

## Build & dependencies

```sh
sh autogen.sh        # bootstrap: autoreconf -i
# or, for development (maintainer-mode, extra warnings, debug symbols):
./autogen.des

./configure
make
make check           # run the full VTC test suite
make distcheck       # full release check — expected to pass before a PR
```

Required dependencies: OpenSSL/libcrypto, PCRE2 (`--enable-pcre2-jit` on by default),
a readline-compatible library (libedit or GNU readline w/ history), a curses library
(ncursesw/ncurses/curses), autoconf/automake/libtool/pkg-config. Building docs/man pages
additionally needs python3, docutils (`rst2man`), and sphinx (`sphinx-build`).

Optional: jemalloc (`--with-jemalloc`, default on Linux), libunwind (`--with-unwind`,
recommended on Alpine), `--with-persistent-storage` (experimental, disabled on s390x).
Sanitizer builds: `--enable-asan`, `--enable-tsan`, `--enable-ubsan`, `--enable-msan`.

To build a subset, `cd` into the subdirectory (`include lib bin vmod etc doc man contrib`)
and run `make` there after a top-level `./configure`.

Note: `bin/varnishlog-json/` is the one exception — it has its own CMake build, not part
of this autotools flow. See [bin/varnishlog-json/AGENTS.md](bin/varnishlog-json/AGENTS.md).

## Before submitting a PR

Read `CONTRIBUTING.md` first. The enforced checklist (from `.forgejo/pull_request_template.md`):
- Configure the tree with `./autogen.des`
- Run `make distcheck` (parallelize on a big machine: `make -j $(($(nproc)*10)) distcheck`)

Non-trivial PRs should follow the style described in Jens Axboe's liburing contributing
guide (linked from `CONTRIBUTING.md`) — code style is FreeBSD `style(9)` (below), commit
message conventions are looser than that guide's C code requirements.

Available (not CI-enforced) static-analysis tooling: `tools/coccinelle/` (Coccinelle
semantic-patch scripts, see its `README.rst` — macro-heavy code can cause silent parse
failures, check with `spatch --parse-c` first), `flint.lnt` (FlexeLint/PC-lint config).

---

## Core concept: VCL

VCL is a domain-specific language for expressing cache policy. It is **compiled to C, then
to a shared library**, and loaded at runtime — it is not interpreted. See
[lib/libvcc/AGENTS.md](lib/libvcc/AGENTS.md) for the compiler internals, subroutine list,
type list, and lifecycle hooks.

## Architecture: management vs. worker split

The daemon (`vinyld`) runs as **two processes** — see [bin/vinyld/AGENTS.md](bin/vinyld/AGENTS.md)
for the full breakdown of what each process owns.

## Testing: VTC (Varnish Test Cases)

Test files use the `.vtc` extension and a custom DSL parsed by `vinyltest`/`varnishtest`.
Every bug fix must have a corresponding `r<N>.vtc` regression test. See
[bin/vinyltest/AGENTS.md](bin/vinyltest/AGENTS.md) for the DSL, running tests, and the
mandatory `-i` flag.

---

## Code style (FreeBSD style(9))

The canonical reference is `https://man.freebsd.org/cgi/man.cgi?query=style&sektion=9`.
Key rules for this codebase:

**Indentation**: Hard tabs. Tab width = 8. Never use spaces for indentation. Continuation
lines get one extra tab.

**Braces** (K&R style):
```c
if (condition) {
    /* body */
}

static void
function_name(args)
{
    /* body */
}
```

**Naming**:
- Functions: `lowercase_with_underscores` for internal; `PREFIX_CamelCase` for public API
  (e.g., `VSL_Next()`, `VRT_fail()`, `BAN_Build()`, `http_Teardown()`)
- Macros: `ALL_CAPS`
- Structs: `struct lowercase_name` — never typedef'd for pointer hiding
- Magic constants: `#define TYPENAME_MAGIC 0x<8hexdigit>` on the line immediately after
  `unsigned magic;` in the struct. This convention applies to every major struct in the
  codebase (see e.g. [bin/vinyld/cache/AGENTS.md](bin/vinyld/cache/AGENTS.md)) — never skip
  it when adding a new struct.

**Comments**: `/* ... */` only. No `//`. No docstrings. No "what" comments — code names
explain what. Only write a comment when the WHY is non-obvious.

**Every `.c` file starts**:
```c
/*-
 * Copyright ...
 * SPDX-License-Identifier: BSD-2-Clause
 * ...
 */

#include "config.h"

#include <system_headers.h>
#include "local_headers.h"
```

**Assertions** (`include/vas.h`):
```c
AN(ptr);           /* assert not NULL / non-zero */
AZ(ret);           /* assert zero / NULL return value */
assert(expr);      /* general assertion */
WRONG("msg");      /* mark unreachable code */
INCOMPL();         /* placeholder: code not yet written */
PTOK(pthread_call()); /* assert pthread call returned 0 */
diagnostic(expr);  /* expensive assert; may be compiled out */
```

Asserts have "negative cost" (developer quote): use them liberally. They save debug time.

**Object lifecycle** (`include/miniobj.h`):
```c
ALLOC_OBJ(ptr, TYPE_MAGIC);       /* calloc + set magic */
FREE_OBJ(ptr);                    /* zero magic, free, NULL ptr */
INIT_OBJ(ptr, TYPE_MAGIC);        /* memset + set magic (in-place) */
FINI_OBJ(ptr);                    /* zero magic, NULL ptr (no free) */
CHECK_OBJ(ptr, TYPE_MAGIC);       /* assert magic (ptr may be NULL → crash) */
CHECK_OBJ_NOTNULL(ptr, MAGIC);    /* assert non-NULL and correct magic */
CHECK_OBJ_ORNULL(ptr, MAGIC);     /* if non-NULL, assert magic */
CAST_OBJ_NOTNULL(to, from, MAGIC);/* type-safe downcast with assert */
TAKE_OBJ_NOTNULL(to, pfrom, MAGIC);/* move pointer out of its home, asserting */
```

**Queue macros** (`include/vqueue.h`): `VTAILQ_*`, `VSTAILQ_*`, `VSLIST_*` — Varnish
wrappers over BSD sys/queue.h. Use these, not raw linked list manipulation.

**Compiler attributes** (`include/vdef.h`):
- `v_noreturn_` — function never returns (after WRONG, VAS_Fail, etc.)
- `v_unused_` — suppress unused warning
- `v_printflike_(fmt_idx, arg_idx)` — enable printf format checking

**Error handling**: No exceptions. Return 0 / NULL on success, error code or message on
failure. Use `AN`/`AZ`/`assert` at every internal API boundary. Validate external input
at entry points; trust internal invariants everywhere else.

**`-Werror` is mandatory**: every warning is an error. The actual `-W...` flag set is
probed per-compiler by `wflags.py` at configure time (`--enable-developer-warnings`), not
a fixed list. Do not suppress warnings with casts or pragmas unless absolutely necessary
and explicitly documented.

**License**: BSD 2-clause or looser only. No GPL, no LGPL.

**`#include "config.h"`**: Must be the **first** include in every `.c` file. This is an
autoconf requirement; it provides platform-specific feature-test macros. Missing it causes
subtle portability failures.
