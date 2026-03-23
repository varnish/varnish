<!--
        Copyright (c) 2016-2026 Varnish Software AS
        SPDX-License-Identifier: BSD-2-Clause
        See LICENSE file for full text of license
-->

[![Compile and Check](https://github.com/varnish/varnish/actions/workflows/check.yml/badge.svg)](https://github.com/varnish/varnish/actions/workflows/check.yml)

# Varnish Cache

This is Varnish Cache, the high-performance HTTP accelerator.
It is [Varnish Software's](https://www.varnish-software.com/) open source downstream version of [Vinyl](https://www.vinyl-cache.org/) where we add features not yet available or deemed out of scope of Vinyl.

Documentation and additional information about Varnish is available on
https://www.varnish.org/

On top of [varnish.org](https://www.varnish.org/), you might want to check out
these links:
- [deb](https://www.varnish.org/docs/install-guide/install-debian-ubuntu/)/[rpm](https://www.varnish.org/docs/install-guide/install-rhel-compatible/) packages can be installed using our third-party repository. This repository include the core package as well as curated vmods from the community.
- said packages are defined and created in [varnish/all-packager](https://github.com/varnish/all-packager)
- the [official docker image](https://hub.docker.com/_/varnish) is defined in
  [varnish/docker-varnish](https://github.com/varnish/docker-varnish), using the
  `deb` packages mentioned above
- the [Varnish Helm chart](https://artifacthub.io/packages/helm/varnish/varnish-cache) is defined and build in [varnish/helm-varnish](https://github.com/varnish/helm-varnish)

Please see the `CONTRIBUTING` file for how to contribute patches and report bugs.
