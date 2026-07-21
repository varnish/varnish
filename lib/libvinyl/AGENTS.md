# lib/libvinyl/ — AGENTS.md

Utility library shared across the codebase: `vsb`, `vjsn`, `vre`, `vss`, `vfil`, `vtim`, `vnum`, `vcli_serve`, and more. (Historically named `libvarnish` upstream; this tree uses `libvinyl`.)

## `struct vsb` (Varnish String Buffer)

Dynamic string builder. **Not** a standard library type — must use the Varnish API. Defined in `lib/libvinyl/vsb.c`, declared in `include/vsb.h`.

Key functions (actual signatures — note most return `int`, not `void`):
```c
struct vsb *VSB_new_auto(void);          /* auto-sized heap buffer; no manual-buffer constructor exists in this codebase */
int         VSB_printf(struct vsb *, const char *fmt, ...);
int         VSB_cat(struct vsb *, const char *str);
int         VSB_putc(struct vsb *, int c);
int         VSB_finish(struct vsb *);    /* NUL-terminate; must call before data/len */
char       *VSB_data(const struct vsb *);/* pointer to string (after finish) */
ssize_t     VSB_len(const struct vsb *); /* length (after finish) */
void        VSB_destroy(struct vsb **);  /* free heap-allocated vsb */
```

Used throughout for error messages, CLI output, code generation, JSON building, etc.

## `txt` type (string slice)

A `txt` is a `struct { const char *b, *e; }` — pointer to start and one-past-end. Used for HTTP header names and values (no NUL terminator required in the buffer). Defined in `include/vdef.h`.

Helpers (`include/vdef.h`):
- `Tlen(t)` — length of the slice (`pdiff((t).b, (t).e)`)
- `Tstr(s)` — converts a NUL-terminated C string `s` **into** a `txt`: `(txt){(s), (s) + strlen(s)}`. (This is the opposite direction from what you might expect — it builds a `txt` from a C string, it does not extract a C string from a `txt`.)
- `Tstreq(t, s)` — compare a `txt` against a C string for equality
- `pdiff(b, e)` — same as `Tlen` but takes raw pointers; returns `size_t`

## Other utilities in this directory

- `vjsn.c` — JSON parsing (used by VCC for VMOD `.vcc` metadata)
- `vre.c` — regex wrapper
- `vss.c` — socket address resolution
- `vfil.c` — file utilities
- `vtim.c` — time utilities
- `vnum.c` — number parsing
- `vcli_serve.c` — CLI protocol server helper

Note: `lib/libvgz/` (gzip support, zlib wrapper) is a separate directory from `libvinyl` — it vendors upstream zlib code kept in sync with the original project; do not hand-modify it casually.
