[![tests](https://github.com/varnish/varnishlog-json/actions/workflows/compile.yml/badge.svg?branch=main)](https://github.com/varnish/varnishlog-json/actions/workflows/compile.yml)

`varnishlog-json` is a simple `JSON` logger for [varnish](https://varnish-cache.org). Think of it as "`varnishlog`, but with a `JSON` output". For example:

``` shell
# the default is to produce NDJSON
$ varnishlog-json
{"req":{"headers":{"host":"localhost:6081","user-agent":"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0","accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8","accept-language":"en-US,en;q=0.5","accept-encoding":"gzip, deflate, br","cookie":"grafana_session=1befa47e1e0dae5765c50152c143834a; grafana_session_expiry=1704753092","upgrade-insecure-requests":"1","sec-fetch-dest":"document","sec-fetch-mode":"navigate","sec-fetch-site":"cross-site","x-forwarded-for":"127.0.0.1","via":"1.1 flamp (Varnish/7.4)","x-varnish":"36"},"method":"GET","url":"/","proto":"HTTP/1.1","hdrBytes":564,"bodyBytes":0},"resp":{"headers":{"server":"SimpleHTTP/0.6 Python/3.11.6","date":"Fri, 12 Jan 2024 00:30:15 GMT","content-type":"text/html; charset=utf-8","content-length":"220"},"proto":"HTTP/1.0","status":"200","reason":"OK","hdrBytes":155,"bodyBytes":220},"timeline":[{"name":"Start","timestamp":1705019415.492248},{"name":"Fetch","timestamp":1705019415.492313},{"name":"Connected","timestamp":1705019415.492479},{"name":"Bereq","timestamp":1705019415.492537},{"name":"Beresp","timestamp":1705019415.493845},{"name":"Process","timestamp":1705019415.493855},{"name":"BerespBody","timestamp":1705019415.494103}],"side":"backend","id":36,"vcl":"reload_20240112_002849_3983566","backend":{"name":"west","rAddr":"127.0.0.1","rPort":8082,"connReused":false},"storage":"malloc Transient"}

# but it can pretty-print too
$ varnishlog-json -p
{
	"req":	{
		"headers":	{
			"host":	"localhost:6081",
			"user-agent":	"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
			"accept":	"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
			"accept-language":	"en-US,en;q=0.5",
...
```

`varnishlog-json` tries to represent what the remote party (the client or the backend) sees. For example, when reporting on a backend transaction, it will ignore modifications made to `bereq` after it was sent, and on the client side, it will ignore any changes the `VCL` makes to the request.

**warning:** Even though the `JSON` structure is explained below, be aware that it is very liable to change before the 1.0.0 release.

# building

You will need:
- `cmake`
- a `C` compiler
- the `varnish` headers (usually from the `varnish-dev` or `varnish-devel` package if not installed with the main package)
- `libcjson` and its headers
- `python-sphinx` if you want to build the documentation
- `jq` to run the tests
- `rst2man` to build the `man` page (usually part of `python-docutils` or `docutils`)

To build:

``` shell
# set up the build directory (you only need to do it once)
cmake -B build

# build and test
cmake --build build/
ctest --test-dir build/

# this should have produce a build/varnishlog-json binary
```

# JSON structure

`varnishlog-json` gets its data from the same source as `varnishlog`, so it's important to understand which tags
are used to produce the output. It can be particularly useful if you want to suppress part of the object
using the `-i/-I/-x/-X` arguments.

We'll use `typescript` notation to describe the object shape:

``` typescript
{
    req: {                                      // describes the request as seen by the remote (either client, or backend)
        headers: Map<string, string>,           // keys (header names) are lowercase, this map is built using ReqHeader,
                                                // BereqHeader, RespUnset, and BerespUnset tags
        method: string,                         // ReqMethod, BereqMethod
        url: string,                            // ReqURL, BereqURL
        proto: string,                          // ReqProtocol, BereqProtocol
        hdrBytes: number,                       // ReqAcct, BereqAcct
        bodyBytes: number,                      // ^ same
    },
    resp: {                                     // describes the remote as seen by the remote
        headers: Map<string, string>,           // keys (header names) are lowercase, uses ReqHeader, BereqHeader, RespUnset, and BerespUnset
        set-cookie?: Array<string>,             // Set-Cookie headers
        proto: string,                          // RespProtocol, BerespProtocol
        status: number,                         // RespStatus, BerespStatus
        reason: string,                         // RespReason, BerespReason,
        hdrBytes: number,                       // ReqAcct, BereqAcct
        bodyBytes: number,                      // ^ same
    },
    handling: "hit" | "miss" | "pass" |"pipe" |
              "streaming-hit" | "fail" | "synth"
              "abandon" | "fetch" | "error",    // how the request was handled
    timeline: Array<{name: string, timestamp: number}> // Timestamp
    side: "backend" | "client",
    id: string,                     // the transaction's vxid
    vcl: string                     // VCL_use
    client?: {                      // ReqStart
        rAddr: string,
        rPort: number,
        sock: string,
    },
    backend?: {                     // BackendOpen (backend-only)
        name: string,
        rAddr: string,
        rPort: number,
        connReused: bool,
    },
    storage?: string,               // Storage (backend-only)
    errors?: Array<string>,         // Error, VCL_Error, FetchError, if the VSL transaction was incomplete
    logs: Array<string>,            // VCL_Log
    links: Array<{                  // Link
        type: string,
        id: string,
        reason: string,
    }>,
}
```

If you use `-g request`, instead of one object per line, `varnishlog-json` will out an array of all objects in the group.

# Docker container

You can build a `docker` container on top of the [varnish image](https://hub.docker.com/_/varnish):

```
docker build -t varnishlog-json .
```

# Notes

Similar to how `varnishlog` behaves, `ESI` and backend transactions are ignored by default.

Use `varnishlog-json -h` to list all possible options.
