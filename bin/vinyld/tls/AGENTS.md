# bin/vinyld/tls/ — AGENTS.md

Implements OpenSSL-based TLS for both client (inbound) and backend (outbound) connections.

Key structs (defined in `cache_tls.h`):

```c
struct vtls_sess {            /* per-connection TLS state */
    unsigned magic;           /* VTLS_SESS_MAGIC 0x4795576c */
    SSL *ssl;
    struct vtls_log log[1];   /* for VSL routing */
    int sni_result;
    char *ja3;                /* JA3 fingerprint */
    struct vtls_buf *buf;     /* TLS record buffer (client-side) */
    void *priv_local;
};

struct vtls_log {             /* routes logs to correct VSL tag */
    struct vsl_log *vsl;
    vxid_t vxid;
    unsigned is_client;       /* SLT_TLS vs SLT_BackendSSL */
};
```

| Struct | Magic |
|--------|-------|
| `struct vtls_sess` | `0x4795576c` |
| `struct vtls_buf` | `0xfb745381` |

Logging macro: `VTLS_LOG(log, tag, ...)` — handles the null-vsl case (backend probe, non-transactional logging) automatically.

VMOD accessors: `VTLS_tls_ctx(ctx)` and `VTLS_ja3(ctx)` (used by `vmod_tls`).

TLS transport registered as `TLS_transport` (see `bin/vinyld/cache/cache_transport.h` for the transport vtable pattern).

TLS certificate and context configuration: `bin/vinyld/mgt/mgt_tls_conf.c`.
