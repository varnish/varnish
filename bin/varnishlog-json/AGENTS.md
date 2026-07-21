# bin/varnishlog-json/ — AGENTS.md

**This is the only downstream-only binary in the repository.** Every other `vinyl*`-prefixed tool (`vinyladm`, `vinylhist`, `vinyllog`, `vinylncsa`, `vinylstat`, `vinyltest`, `vinyltop`, and the `vinyld` daemon itself) originates from the upstream "vinyl" open-source project, and changes to those may need upstreaming. `varnishlog-json` does not exist upstream — changes here are downstream-only and never need to go back to vinyl.

JSON-format VSL output (see [../../lib/libvinylapi/AGENTS.md](../../lib/libvinylapi/AGENTS.md) for VSL concepts).

## Build system — different from the rest of the repo

Unlike every other tool in `bin/`, `varnishlog-json` does **not** build via the top-level autotools flow (`./configure && make`). It has its own independent CMake build:

```sh
cmake -B build
cmake --build build/
ctest --test-dir build/
```

Requires `libcjson`. See `bin/varnishlog-json/README.md` in this directory for full build details, the JSON output schema, and Docker build instructions — that file already documents this thoroughly; this AGENTS.md file exists mainly to flag the CMake-vs-autotools trap for anyone assuming the whole repo builds uniformly.
