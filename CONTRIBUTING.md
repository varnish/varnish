# Contributing to Varnish Cache

The official development happens on github: https://github.com/varnish/varnish>

We prefer patches as [pull requests](https://github.com/varnish/varnish/compare/main) onto the `main` branch.

Please use [issues](https://github.com/varnish/varnish/issues/new/choose) for bug reports.

Our main project communication is through our the [Varnsih discord Channel](https://discord.com/invite/EuwdvbZR6d).
You can use it to ask about code, configuration, potential bugs, etc.

## General process

## [Pull Requests](https://github.com/varnishcache/varnish-cache/pull)

Pull requests are handled like other tickets.

Trivial pull requests (fix typos, etc) are welcomed, but they may be committed
by a core team member and the author credited in the commit message.

For anything non trivial, please take [Jens Axboe's excellent contributing
guide](https://github.com/axboe/liburing/blob/master/CONTRIBUTING.md) as
guidance.

Notable differences for Varnish Cache are:

* For code style, we broadly follow bsd [style(9)](https://man.freebsd.org/cgi/man.cgi?query=style&sektion=9)

* Regarding commit messages, we are usually less strict

* For testing ``make distcheck`` should pass
