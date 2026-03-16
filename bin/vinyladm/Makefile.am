#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS = varnishadm

varnishadm_SOURCES = vinyladm.c

varnishadm_CFLAGS = @LIBEDIT_CFLAGS@

varnishadm_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvarnishapi.la \
	$(top_builddir)/lib/libvinyl/libvarnish.la \
	${PTHREAD_LIBS} ${RT_LIBS} ${NET_LIBS} @LIBEDIT_LIBS@ ${LIBM}
