# bin/vinyltest/ — AGENTS.md (VTC testing)

Test files use the `.vtc` extension and a custom DSL parsed by this tool. The `bin_PROGRAMS` target actually built is named `varnishtest`; `vtest` is a `make`-time hardlink alias to the same binary — either name works, but `varnishtest` is the real binary if you need to reference it precisely (e.g. in scripts).

Test locations:
- `bin/vinyltest/tests/` — core daemon tests, prefixed by category: `b*` (basic functionality), `r*` (regression tests, one per bug fix), plus many other single-letter category prefixes (`c*`, `d*`, `e*`, `f*`, `g*`, `h*`, `i*`, `j*`, `l*`, `m*`, `o*`, `p*`, `s*`, `t*`, `u*`, `v*`, `x*`, `T*`)
- `vmod/tests/` — per-vmod tests (`<name>_*.vtc`)

## Running tests

```sh
make check                                   # full test suite (uses in-tree binaries automatically)
bin/vinyltest/vtest -i -v tests/b00000.vtc   # single test
```

**The `-i` flag is mandatory** when invoking `vtest` / `varnishtest` directly. Without it the harness uses **system-installed** binaries instead of the in-tree build.

## VTC DSL (not C, not shell — its own language)

```vtc
vtest "Test description"

feature ipv4          # skip test if this feature is absent
feature cmd "curl"    # skip if external tool missing

server s1 {           # mock HTTP backend
    rxreq
    txresp -hdr "X-Foo: bar" -body "hello"
} -start

varnish v1 -vcl+backend {   # daemon instance with inline VCL
    sub vcl_recv {
        set req.http.X-Test = "1";
    }
} -start

varnish v1 -cliok "param.set default_ttl 10"  # CLI commands

client c1 {           # HTTP client
    txreq -url "/" -hdr "Host: example.com"
    rxresp
    expect resp.status == 200
    expect resp.http.X-Foo == "bar"
} -run

varnish v1 -expect cache_miss == 1    # VSC counter check
varnish v1 -expect n_object == 1

logexpect l1 -v v1 -g request {       # VSL assertions
    expect * * ReqURL "^/$"
    expect * * RespStatus "200"
} -start -wait
```

Key VTC commands: `vtest`, `varnish`, `server`, `client`, `feature`, `logexpect`, `process`, `barrier`, `delay`, `shell`, `filewrite`, `syslog`.

**Convention**: every bug fix must have a corresponding `r<N>.vtc` regression test.

## Other test-related tools

- `tools/vtc-bisect.sh` — bisects git history to find which commit broke a given `.vtc` test
- `tools/vtest.sh` — CI test-runner driver script (clones/builds/runs the full suite; do not point `TMPDIR` at `/tmp`, it explicitly warns against this)
