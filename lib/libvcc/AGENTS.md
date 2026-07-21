# lib/libvcc/ — AGENTS.md

## VCL — Varnish Configuration Language

VCL is a domain-specific language for expressing cache policy. It is **compiled to C, then to a shared library**, and loaded at runtime — it is not interpreted.

VCL consists of subroutines (`sub vcl_recv`, `sub vcl_backend_response`, etc.) that map to steps in the request processing state machine (see [bin/vinyld/cache/AGENTS.md](../../bin/vinyld/cache/AGENTS.md)). Each subroutine ends with a `return(action)` that drives the FSM transition.

VCL types: `ACL`, `BACKEND`, `BLOB`, `BOOL`, `BYTES`, `DURATION`, `ENUM`, `HEADER`, `HTTP`, `INT`, `IP`, `OBJECT`, `REAL`, `REGEX`, `STEVEDORE`, `STRING`, `TIME`.

VCL subroutines (client-side): `vcl_recv`, `vcl_pipe`, `vcl_pass`, `vcl_hash`, `vcl_purge`, `vcl_miss`, `vcl_hit`, `vcl_deliver`, `vcl_synth`.

VCL subroutines (backend-side): `vcl_backend_fetch`, `vcl_backend_response`, `vcl_backend_error`.

VCL lifecycle: `vcl_init`, `vcl_fini`.

## VCC — VCL Compiler

VCC translates VCL source into C code. Lives entirely in `lib/libvcc/`.

Key source files:
- `vcc_compile.c` — orchestration, code generation entry point
- `vcc_token.c` — lexer and error reporting
- `vcc_parse.c` — recursive-descent parser
- `vcc_expr.c` — expression parsing and type checking
- `vcc_symb.c` — symbol table management
- `vcc_xref.c` — cross-reference validation (unused symbols, etc.)
- `vcc_vmod.c` — VMOD import: reads `.vcc` + embedded JSON, generates C bindings
- `vcc_types.c` — type system
- `vcc_acl.c` — ACL compilation
- `vcc_backend.c` — backend/probe parsing

Main context struct: `struct vcc` (VCC_MAGIC `0x24ad719d`) — holds symbol tables, source list, output buffers, error state.

Code generation helpers: `Fh(tl, ...)` (emit to header), `Fc(tl, ...)` (emit to C body), `Fb(tl, ...)` (emit to current function body).

VCC is invoked by the management process via `bin/vinyld/mgt/mgt_vcc.c`. The resulting `.so` is `dlopen`'d in the worker process.

## Build-generated files

`lib/libvcc/generate.py` produces these files at build time — they will **not** exist in a fresh, unbuilt checkout, and must not be hand-edited even after they appear:
- `include/vcl.h` — defines `VCL_MET_*` method bitmaps and `VCL_RET_*` return constants
- `include/tbl/vcl_returns.h` — canonical list of return actions per method
- `include/tbl/vrt_stv_var.h` — VCL stevedore variable table

`lib/libvcc/vmodtool.py` generates the C bindings for VMODs from their `.vcc` files (see [vmod/AGENTS.md](../../vmod/AGENTS.md)).

Key files elsewhere in the repo relevant to VCL/VCC:
- `include/vrt.h` — VCL Runtime API; everything a VMOD or VCL-generated C code can call
- `include/tbl/vcl_states.h` — VCL state machine states (COLD, WARM, AUTO)
- `etc/builtin.vcl` — the default VCL loaded when no user VCL is given

## Add a VCL return action

Edit `include/tbl/vcl_returns.h` following the existing `VCL_RET_MAC` pattern. Note this file is build-generated (see above) — edit the generation logic in `generate.py` if the change needs to persist across rebuilds, not the generated file directly, unless the pattern already exists as static input consumed by the generator (check `generate.py` before editing).
