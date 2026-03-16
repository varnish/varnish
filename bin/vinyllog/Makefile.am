#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS = varnishlog

varnishlog_SOURCES = \
	vinyllog.c \
	vinyllog_options.h

varnishlog_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvarnishapi.la \
	${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}
