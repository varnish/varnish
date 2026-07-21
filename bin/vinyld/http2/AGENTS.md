# bin/vinyld/http2/ — AGENTS.md

Implements the HTTP/2 protocol layer.

Key files:
- `cache_http2_session.c` — session lifecycle, stream management
- `cache_http2_proto.c` — frame read/write, flow control
- `cache_http2_hpack.c` — HPACK glue; the actual HPACK codec (`vhp_decode.c`, `vhp_table.c`, `vhp_gen_hufdec.c`) lives in the separate `bin/vinyld/hpack/` directory, not here
- `cache_http2_deliver.c` / `cache_http2_send.c` — response delivery
- `cache_http2_reqbody.c` — request body handling

HPACK static table and Huffman coding tables live in:
- `include/tbl/vhp_static.h`
- `include/tbl/vhp_huffman.h`

HTTP/2 protocol constants are X-macro tables (see [include/tbl/AGENTS.md](../../../include/tbl/AGENTS.md)):
- `include/tbl/h2_frames.h` — frame types
- `include/tbl/h2_settings.h` — SETTINGS parameters
- `include/tbl/h2_error.h` — error codes
- `include/tbl/h2_stream.h` — stream states

HTTP/2 receive buffers use a special stevedore: `stv_h2_rxbuf` (transient, not user-configurable — see [../storage/AGENTS.md](../storage/AGENTS.md)).
