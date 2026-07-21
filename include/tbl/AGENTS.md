# include/tbl/ — AGENTS.md

`include/tbl/` contains 46 header files (plus a `README` and `style.py`, not headers) that define enumerated sets as pure macro tables. This X-macro pattern lets the same data source generate enums, switch cases, documentation strings, and validation logic without duplication.

Usage pattern:
```c
/* In a .c file: */
#define SLTM(tag, flags, sdesc, ldesc)  /* ... your expansion ... */
#include "tbl/vsl_tags.h"
/* The header #undef SLTM at the end */
```

Key tables and their macros:

| File | Macro | Used for |
|------|-------|----------|
| `vsl_tags.h` | `SLTM(tag, flags, sdesc, ldesc)` | VSL tag enum, docs |
| `vsl_tags_http.h` | `SLTM(...)` | HTTP-specific VSL tags |
| `vcl_returns.h` | `VCL_RET_MAC(l, U, bitmap)` / `VCL_MET_MAC(l, U, t, m)` | VCL return actions — **build-generated**, see below |
| `vcl_states.h` | `VCL_STATE(U, l)` | VCL state machine states |
| `http_headers.h` | `HTTP_HDR(n, s, f)` | HTTP header name constants |
| `params.h` | `PARAM_SIMPLE(...)` / `PARAM(...)` | Runtime parameters |
| `sess_close.h` | `SESS_CLOSE(nm, stat, err, desc)` | Session close reason codes |
| `locks.h` | `LOCK(nam)` | Lock object definitions |
| `feature_bits.h` | `FEATURE_BIT(U, l, d)` | Feature flags |
| `experimental_bits.h` | `EXP_BIT(U, l, d)` | Experimental feature flags |
| `symbol_kind.h` | `SYMKIND(U, l)` | VCC symbol kinds |
| `h2_frames.h` | `H2_FRAME(l, U, t, f, ...)` | HTTP/2 frame types |
| `h2_settings.h` | `H2_SETTING(l, U, v, ...)` | HTTP/2 settings |
| `h2_error.h` | `H2_ERROR(l, v, sc, t)` | HTTP/2 error codes |
| `vrt_stv_var.h` | `VRTSTVVAR(nm, vt, ct, def)` | VCL stevedore variables — **build-generated**, see below |

Files marked "NB: This file is machine generated, DO NOT EDIT!" must not be edited by hand; regenerate via the build system.

## Build-generated files

Two files in this table (`vcl_returns.h` and `vrt_stv_var.h`) are produced by `lib/libvcc/generate.py` at build time, just like `include/vcl.h` — they will **not** exist in a fresh, unbuilt checkout. All other tables listed above are static, hand-authored files checked into git.

## Add a VSL tag

1. Add to `vsl_tags.h`:
   ```c
   SLTM(MyTag, 0, "short desc", "long description of the tag and its format")
   ```
2. Use in daemon code: `VSLb(req->vsl, SLT_MyTag, "format %s", value)`

(See [../../lib/libvinylapi/AGENTS.md](../../lib/libvinylapi/AGENTS.md) for the full VSL reader/writer picture.)

## Add a runtime parameter

1. Add to `params.h`:
   ```c
   PARAM_SIMPLE(
       /* name */   my_param,
       /* type */   uint,
       /* min */    "1",
       /* max */    "1000",
       /* def */    "10",
       /* units */  "milliseconds",
       /* descr */  "What this parameter controls."
   )
   ```
2. Access in daemon: `cache_param->my_param`
