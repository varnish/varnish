#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS = vinyladm

vinyladm_SOURCES = vinyladm.c

vinyladm_CFLAGS = @LIBEDIT_CFLAGS@

vinyladm_LDADD = \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	$(top_builddir)/lib/libvarnish/libvarnish.la \
	${PTHREAD_LIBS} ${RT_LIBS} ${NET_LIBS} @LIBEDIT_LIBS@ ${LIBM}
