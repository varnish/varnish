ACLOCAL_AMFLAGS = -I m4 -I .

SUBDIRS = include lib bin vmod etc doc man contrib

TESTS = tools/magic_check.sh

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = varnishapi.pc

m4dir = $(datadir)/aclocal
m4_DATA = vinyl.m4 vinyl-legacy.m4

CLEANFILES = \
	cscope.in.out \
	cscope.out \
	cscope.po.out \
	witness.dot \
	witness.svg

EXTRA_DIST = \
	$(TESTS) \
	README.md \
	LICENSE \
	autogen.sh \
	varnishapi.pc.in \
	vinyl.m4 \
	vinyl-legacy.m4 \
	vsc.am \
	vtc.am \
	wflags.py

CONFIGURE_DEPENDENCIES = wflags.py

AM_DISTCHECK_CONFIGURE_FLAGS = \
    --enable-developer-warnings \
    --enable-debugging-symbols \
    --enable-dependency-tracking \
    --with-contrib \
    CFLAGS="$(EXTCFLAGS)"

if WITH_UNWIND
AM_DISTCHECK_CONFIGURE_FLAGS += --with-unwind
endif

install-data-local:
	if test "${VINYL_STATE_DIR}" = "$(DESTDIR)$(localstatedir)/vinyl-cache" ; then \
		$(install_sh) -d -m 0755 "${VINYL_STATE_DIR}"; \
	fi

distclean-local:
	-find . '(' -name '*.gcda' -o -name '*.gcda' ')' -exec rm '{}' ';'

distcleancheck_listfiles = \
	find . -type f -exec sh -c 'test -f $(srcdir)/$$1 || echo $$1' \
		sh '{}' ';'

vtest-clean:
	$(am__remove_distdir)

# XXX: This is a hack to ensure we have a built source tree when
# running make dist If we had used non-recursive make we could have
# solved it better, but we don't, so use this at least for now.
LICENSE: all

# XXX: This is a similar hack to ensure we have a built vinyltest
# (and technically any other binary that may be involved in a VTC)
# before we try to run tests anywhere in the tree.
check-recursive: all

# XXX: This is the exact same hack since some parts of the documentation
# are generated as regular targets but needed by the html special target.
html-recursive: all

cscope:
	-rm -f cscope*
	find . -name '*.[hcS]' > cscope.files
	cscope -b

gcov_digest:
	${PYTHON} tools/gcov_digest.py -o _gcov

witness.dot: all
	$(MAKE) check AM_VTC_LOG_FLAGS=-pdebug=+witness
	$(AM_V_GEN) $(srcdir)/tools/witness.sh witness.dot bin/vinyltest/ \
		vmod/

.dot.svg:
	$(AM_V_GEN) $(DOT) -Tsvg $< >$@

witness: witness.svg

update:
	git submodule sync
	git submodule update --remote bin/vinyltest/vtest2
	git commit -m 'Update vtest2' bin/vinyltest/vtest2 || true

.PHONY: cscope witness.dot update
