# bin/vinyld/cache/ — AGENTS.md

Core request-processing code for the worker process: HTTP, ban, hash, ESI, the request state machine. All major structs here begin with `unsigned magic` immediately followed by a `#define TYPE_MAGIC 0x<hex>` constant, asserted at runtime via `CHECK_OBJ*` macros. Never skip this pattern when adding a new struct.

## Key data structures

All defined in `bin/vinyld/cache/cache.h`:

| Struct | Magic | Role |
|--------|-------|------|
| `struct sess` | `0x2c2f9c5a` | TCP session: fd, pool, TLS state, timestamps, workspace |
| `struct req` | `0xfb4abf6d` | Client request: http headers, response, objcore, worker, session, VSL |
| `struct busyobj` | `0x23b95567` | Backend fetch: bereq, beresp, fetch filters, timing |
| `struct objcore` | `0x4d301302` | Cached object metadata: TTL, grace, refcount, ban pointer, LRU |
| `struct worker` | `0x6391adcf` | Thread worker: pool, stats (VSC), VSL log, task queue |
| `struct http` | `0x6428b5c9` | HTTP header collection: array of `txt` structs |
| `struct ws` | `0x35fac554` | Linear workspace allocator (s/f/r/e pointers) |

## Request lifecycle (state machine)

Defined in `cache_req_fsm.c` via the `REQ_STEPS` X-macro:

```
transport → restart → recv → pipe
                           → pass
                           → lookup → purge
                                    → miss → fetch → deliver → transmit → finish
                                           → hit  → deliver
                           → vclfail → synth
```

Each step is a `req_state_f` function named `cnt_<step>`. VCL subroutines are invoked at transition points: `VCL_recv()`, `VCL_hash()`, `VCL_miss()`, `VCL_hit()`, `VCL_deliver()`, etc.

The FSM is re-entered via `struct req->req_step` pointer; state transitions happen by setting that pointer and returning.

## VFP/VDP filter chains

`cache_filter.h` defines the body transformation pipeline.

- **VFP** (Varnish Fetch Processors): transform the object body during backend fetch
- **VDP** (Varnish Deliver Processors): transform the object body during client delivery

Each filter is a `struct vfp` / `struct vdp` with callbacks:
- `init` — set up filter state
- `pull` (VFP) / `push` (VDP) — process a chunk of data
- `fini` — tear down

Filters are chained; each passes data to the next. Examples: gzip, gunzip, ESI parser, chunked transfer encoding, `varnishlog-json` body capture.

## Director interface

`cache_director.h` defines `struct director` — the vtable for backend and director objects:

```c
struct director {
    unsigned            magic;   /* DIRECTOR_MAGIC */
    const char          *name;
    director_resolve_f  *resolve;  /* pick a concrete backend */
    director_healthy_f  *healthy;
    director_gethdrs_f  *gethdrs;  /* make a backend connection and get response headers */
    director_finish_f   *finish;
    director_panic_f    *panic;
    ...
};
```

`resolve` is called on directors (round-robin, hash, shard) to return a concrete backend. `vmod_directors` implements this interface.

VMOD lifecycle: `VRT_AddDirector(ctx, dir, ...)` / `VRT_DelDirector(dir **)`.

## Ban system

`cache_ban*.c` — lazy cache invalidation.

- `ban()` VCL/CLI command adds a ban expression to the ban list
- Objects are checked against pending bans **on next access** (lazy)
- Ban lurker (`cache_ban_lurker.c`): background thread proactively tests cold objects
- `struct ban` holds a compiled ban expression
- `struct objcore->ban` points to the last ban the object was tested against; objects with `ban < head_of_ban_list` need testing

Ban expressions reference object attributes (URL, headers, etc.) defined in `include/tbl/ban_vars.h`.

## Workspace allocation

Short-lived allocations in request context use the **workspace** (`struct ws`), not `malloc`. The workspace is a simple linear allocator reset at the end of each request.

Key functions (declared in `cache.h`, `WS_Rollback` in `cache_vinyld.h`):
```c
void      *WS_Alloc(struct ws *, unsigned len);          /* returns NULL if out of space */
void      *WS_Copy(struct ws *, const void *, int len);  /* copy bytes into workspace */
char      *WS_Printf(struct ws *, const char *fmt, ...); /* printf into workspace */
unsigned   WS_ReserveSize(struct ws *, unsigned len);     /* reserve up to len bytes, commit later */
unsigned   WS_ReserveAll(struct ws *);                    /* reserve all remaining space */
void       WS_ReleaseP(struct ws *, const char *ptr);     /* commit reserved bytes up to ptr */
void       WS_Rollback(struct ws *, uintptr_t snap);      /* undo to snapshot */
uintptr_t  WS_Snapshot(struct ws *);                      /* take snapshot for rollback */
```

Note: `WS_Reserve()` was removed from this codebase; use `WS_ReserveSize()` or `WS_ReserveAll()` instead. Do **not** free individual workspace allocations — the whole workspace resets at request end.
