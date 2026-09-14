#

TESTS = @VTC_TESTS@

include $(top_srcdir)/vtc.am

DISTCLEANFILES = _.ok

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	-I$(top_builddir) \
	-I$(top_srcdir)/lib/libvgz

AM_CFLAGS = \
	-DVTEST_WITH_VTC_LOGEXPECT \
	-DVTEST_WITH_VTC_VARNISH \
	-DVTEST_WITH_VTC_VSM \
	-DTOP_BUILDDIR='"${top_builddir}"' \
	${OPENSSL_CFLAGS} ${LIBCRYPTO_CFLAGS}

# used in LDADD and LIBADD
addlibs = \
	$(top_builddir)/lib/libvinylapi/libvarnishapi.la \
	$(top_builddir)/lib/libvinyl/libvarnish.la \
	$(top_builddir)/lib/libvgz/libvgz.la \
	${PTHREAD_LIBS} ${NET_LIBS} ${LIBM} -ldl \
	${OPENSSL_LIBS} ${LIBCRYPTO_LIBS}

varnishspecific_src = \
	vtc_logexp.c \
	vtc_vsm.c \
	vtc_varnish.c

EXTRA_DIST = \
	$(top_srcdir)/bin/vinyltest/tests/*.vtc \
	$(top_srcdir)/bin/vinyltest/tests/common.pem \
	$(top_srcdir)/bin/vinyltest/tests/README \
	test_assets/*.bin

lib_LTLIBRARIES = libvtest_ext_varnish.la

bin_PROGRAMS =	varnishtest

if HAVE_VTEST
############################################################
## varnishtest from submodule

# for -i invocation / a00000.vtc
all-local: vtest

vtest: varnishtest
	ln -f varnishtest vtest

install-exec-hook:
	ln -f $(DESTDIR)$(bindir)/varnishtest$(EXEEXT) \
	   $(DESTDIR)$(bindir)/vtest$(EXEEXT)

uninstall-hook:
	rm -f $(DESTDIR)$(bindir)/vtest$(EXEEXT)

nodist_varnishtest_SOURCES = \
		vtest2/src/hpack.h \
		vtest2/src/cmds.h \
		vtest2/src/vtc.h \
		vtest2/src/teken.c \
		vtest2/src/teken.h \
		vtest2/src/teken_scs.h \
		vtest2/src/teken_subr.h \
		vtest2/src/teken_subr_compat.h \
		vtest2/src/teken_wcwidth.h \
		vtest2/src/vtc.c \
		vtest2/src/vtc_barrier.c \
		vtest2/src/vtc_client.c \
		vtest2/src/vtc_gzip.c \
		vtest2/src/vtc_haproxy.c \
		vtest2/src/vtc_h2_enctbl.h \
		vtest2/src/vtc_h2_hpack.c \
		vtest2/src/vtc_h2_priv.h \
		vtest2/src/vtc_h2_stattbl.h \
		vtest2/src/vtc_h2_tbl.c \
		vtest2/src/vtc_http.c \
		vtest2/src/vtc_http.h \
		vtest2/src/vtc_http2.c \
		vtest2/src/vtc_log.h \
		vtest2/src/vtc_log.c \
		vtest2/src/vtc_misc.c \
		vtest2/src/vtc_main.c \
		vtest2/src/vtc_process.c \
		vtest2/src/vtc_proxy.c \
		vtest2/src/vtc_server.c \
		vtest2/src/vtc_sess.c \
		vtest2/src/vtc_subr.c \
		vtest2/src/vtc_syslog.c \
		vtest2/src/vtc_tls.c \
		vtest2/src/builtin_cert.h \
		vtest2/src/vtc_tunnel.c \
		vtest2/src/vtest_api.h \
		vtest2/lib/vudp.h \
		vtest2/lib/vudp.c \
		$(varnishspecific_src)

VTEST_CPPFLAGS += -I$(srcdir)/vtest2/src

varnishtest_CPPFLAGS = $(AM_CPPFLAGS) \
	-I$(srcdir)/vtest2/lib \
	$(VTEST_CPPFLAGS)

varnishtest_CFLAGS = $(AM_CFLAGS)

varnishtest_LDADD = ${addlibs}

# would only be needed for vtest, but as both are the same atm...
varnishtest_LDFLAGS = $(AM_LDFLAGS) -rdynamic

teken.c: teken_state.h

teken_state.h:	$(srcdir)/vtest2/src/sequences $(srcdir)/vtest2/src/gensequences
	awk -f $(srcdir)/vtest2/src/gensequences $(srcdir)/vtest2/src/sequences \
	    > $@_
	mv $@_ $@

vtc_h2_hpack.c: vtc_h2_dectbl.h
vtc_h2_dectbl.h: $(srcdir)/vtest2/src/huffman_gen.py $(srcdir)/vtest2/src/tbl/vhp_huffman.h
	$(PYTHON) $(srcdir)/vtest2/src/huffman_gen.py \
	    $(srcdir)/vtest2/src/tbl/vhp_huffman.h > $@_
	mv $@_ $@

# this path is weird, but does seem to make sense to clean up until we remove
# varnishtest from submodule
EXTRA_DIST += $(srcdir)/vtest2/src/../tests/*.vtc \
	vtest2/src/gensequences \
	vtest2/src/sequences \
	vtest2/src/teken.3 \
	vtest2/src/huffman_gen.py \
	vtest2/src/tbl/tls_alert_tbl.h \
	vtest2/src/tbl/tls_cmds_tbl.h \
	vtest2/src/tbl/tls_proto_tbl.h \
	vtest2/src/tbl/vhp_huffman.h

BUILT_SOURCES = \
	teken_state.h \
	vtc_h2_dectbl.h

CLEANFILES = \
	$(BUILT_SOURCES)		\
	vtest

else !HAVE_VTEST
############################################################
## external vtest - varnishtest wrapper

# libdummy is to get the libtool wrapper for in-tree LD_LIBRARY_PATH setting
lib_LTLIBRARIES += libdummy.la

libdummy_la_SOURCES = libdummy.c

nodist_varnishtest_SOURCES = varnishtest.c
varnishtest_LDADD = libdummy.la
varnishtest_CPPFLAGS = $(AM_CPPFLAGS) $(VTEST_CPPFLAGS)
varnishtest_CFLAGS = $(AM_CFLAGS) -DLIBDIR=\"${libdir}\"

endif !HAVE_VTEST

############################################################
## libvtest_ext_varnish

libvtest_ext_varnish_la_SOURCES = \
		vtest_ext_varnish.c \
		vtest_ext_varnish.h \
		$(varnishspecific_src)

libvtest_ext_varnish_la_CPPFLAGS = $(AM_CPPFLAGS) $(VTEST_CPPFLAGS)

libvtest_ext_varnish_la_LIBADD = $(addlibs)

############################################################
## automake
##
## automake (rightfully) includes all sources by default, but for the vtest
## migration, we really only want it to include what it has

EXTRA_DIST += $(nodist_varnishtest_SOURCES)


############################################################
## maintainer convenience

.PHONY: flint flint-local

flint-local:
	$(SHELL) flint.sh
