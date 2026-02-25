---

name: "Pull Request Template"
about: "Template for all Pull Requests"

---

## Checklist

- [ ] I have read, understood and followed [CONTRIBUTING.md](https://github.com/varnishcache/varnish-cache/src/branch/main/CONTRIBUTING.md)
- [ ] I used ``autogen.des`` to configure the source tree
- [ ] I called ``make distcheck`` and it completed without error (recommended to call ``make -j $(($(nproc) * 10)) distcheck`` for short runtime if you have enough RAM)
