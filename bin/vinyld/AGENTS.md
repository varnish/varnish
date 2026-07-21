# bin/vinyld/ — AGENTS.md

`bin/vinyld/` is the main Varnish daemon. It runs as **two processes**:

**Management process** (`bin/vinyld/mgt/`):
- Supervisor; never handles HTTP traffic
- Loads and compiles VCL (via `mgt_vcc.c` → `lib/libvcc/`, see [lib/libvcc/AGENTS.md](../../lib/libvcc/AGENTS.md))
- Manages runtime parameters (`mgt_param.c`; params defined in `include/tbl/params.h`)
- Sets up VSM segments (`mgt_shmem.c`)
- Handles CLI connections (`mgt_cli.c`)
- Forks and supervises the worker; restarts it on crash (`mgt_child.c`)
- Configures TLS (`mgt_tls_conf.c`, see [tls/AGENTS.md](tls/AGENTS.md))

**Worker process** (`bin/vinyld/cache/`, see [cache/AGENTS.md](cache/AGENTS.md)):
- Handles all HTTP traffic
- Forked by mgt; if it crashes, mgt restarts it cleanly
- Communicates with mgt via VSM segments and a CLI pipe
- Accepts connections via `bin/vinyld/acceptor/`
- Multiplexes idle connections via `bin/vinyld/waiter/` (epoll or kqueue)

## Subdirectory map

```
acceptor/  TCP/UDS connection acceptance
cache/     core request processing, HTTP, ban, hash, ESI — see cache/AGENTS.md
common/    shared VSM/VSC init between mgt and worker
hash/      hash table implementations (classic, critbit, simple_list) and mgt_hash.c
hpack/     HPACK codec (vhp_decode.c, vhp_table.c, vhp_gen_hufdec.c) — used by http2/, see http2/AGENTS.md
http1/     HTTP/1.x protocol
http2/     HTTP/2 protocol (frames, session) — see http2/AGENTS.md
mgt/       management process (VCL load, CLI, params, child supervision)
proxy/     PROXY protocol implementation (cache_proxy.h, cache_proxy_proto.c)
storage/   pluggable object storage (stevedore interface + backends) — see storage/AGENTS.md
tls/       OpenSSL TLS (client and backend) — see tls/AGENTS.md
waiter/    epoll/kqueue connection multiplexer
fuzzers/   fuzz targets (esi_parse_fuzzer.c)
```

Note: HPACK's codec implementation lives in `hpack/`, separate from `http2/` — `http2/cache_http2_hpack.c` is the glue that calls into it, not the codec itself.
