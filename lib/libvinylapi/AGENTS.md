# lib/libvinylapi/ — AGENTS.md

Public API library: VSL, VSM, VSC client implementations. (Historically named `libvarnishapi` upstream; this tree uses `libvinylapi`.)

## VSL — Varnish Shared Log

VSL is a high-performance, lock-free shared memory ring buffer for structured transaction logging. Each record contains a tag (8-bit enum), a VXID (transaction ID), and a payload string.

Key files:
- `include/vapi/vsl.h` — public reader API
- `include/vapi/vsl_int.h` — on-disk/in-memory format (record layout, constants)
- `include/tbl/vsl_tags.h` — tag definitions via `SLTM(tag, flags, sdesc, ldesc)` macro
- `include/tbl/vsl_tags_http.h` — HTTP-specific tags
- `lib/libvinylapi/vsl.c` — reader implementation
- `lib/libvinylapi/vsl_cursor.c` — cursor management
- `lib/libvinylapi/vsl_dispatch.c` — query/dispatch engine (VSLQ)

Key structs: `struct VSL_data` (reader context), `struct VSL_cursor`, `struct VSLC_ptr` (record pointer — access via `VSL_TAG()`, `VSL_ID()`, `VSL_CDATA()`, `VSL_LEN()`).

Grouping modes: `VSL_g_raw`, `VSL_g_vxid`, `VSL_g_request`, `VSL_g_session`.

Writing from the daemon: use `VSLb(vsl, SLT_TagName, fmt, ...)` where `vsl` is a `struct vsl_log *` embedded in `struct req`, `struct busyobj`, etc. (see [bin/vinyld/cache/AGENTS.md](../../bin/vinyld/cache/AGENTS.md)). For non-transactional logs (no VXID): `VSL(tag, vxid, fmt, ...)`.

Reading tools: `vinyllog`, `vinylncsa`, `varnishlog-json` (see [bin/varnishlog-json/AGENTS.md](../../bin/varnishlog-json/AGENTS.md)).

### Add a new VSL tag

1. Add to `include/tbl/vsl_tags.h`:
   ```c
   SLTM(MyTag, 0, "short desc", "long description of the tag and its format")
   ```
2. Use in daemon code: `VSLb(req->vsl, SLT_MyTag, "format %s", value)`

## VSM — Varnish Shared Memory

VSM is the mmap-based IPC layer that underlies VSL and VSC. Processes communicate by reading/writing named segments within a VSM directory.

Two directories per run:
- `_.vsm_mgt` — segments owned by the management process
- `_.vsm_child` — segments owned by the worker process

Segment categories: `"Log"` (VSL), `"Stat"` (VSC), `"StatDoc"` (VSC documentation).

Key files:
- `include/vapi/vsm.h` — public client API
- `lib/libvinylapi/vsm.c` — client implementation
- `bin/vinyld/common/common_vsmw.c` — daemon-side segment writer

Key type: `struct vsm_fantom` — client-side reference to a VSM chunk, with `.b`/`.e` boundary pointers to the mapped payload.

Status flags from `VSM_Status()`: `VSM_MGT_RUNNING`, `VSM_WRK_RUNNING`, `VSM_WRK_RESTARTED`, etc.

## VSC — Varnish Statistics Counters

VSC exposes performance counters and gauges in shared memory, consumed by `vinylstat`, `vinyltop`, and external monitoring.

Counter semantics:
- `'c'` — counter (monotonically increasing, e.g. total requests)
- `'g'` — gauge (current value, e.g. open connections)
- `'b'` — bitmap

Display formats: `'i'` (integer), `'B'` (bytes, with unit scaling), `'d'` (duration), `'b'` (bitmap).

Key files:
- `include/vapi/vsc.h` — public API
- `lib/libvinylapi/vsc.c` — client implementation
- `include/tbl/vsc_levels.h` — verbosity levels (info, diag, debug)

Counters are defined in `.vsc` files under `lib/libvsc/` (e.g. `lib/libvsc/VSC_main.vsc`, `VSC_lck.vsc`, `VSC_mempool.vsc`, `VSC_mgt.vsc`, `VSC_sma.vsc`, `VSC_smf.vsc`, `VSC_smu.vsc`, `VSC_vbe.vsc`, `VSC_vcp.vsc`, `VSC_waiter.vsc`) plus per-vmod files like `vmod/VSC_debug.vsc`. The build system generates the corresponding C structs. Access in daemon code: `wrk->stats->counter_name`.

Key type: `struct VSC_point` — single counter descriptor with `volatile uint64_t *ptr`, semantics char, format char, level, and descriptions.

### Add a VSC counter

1. Edit the relevant `.vsc` file (e.g., `lib/libvsc/VSC_main.vsc`):
   ```rst
   .. vinyl_vsc:: my_counter
       :type: counter
       :level: info
       :oneliner: Count of my events
   ```
2. Rebuild; access via `wrk->stats->my_counter++`
