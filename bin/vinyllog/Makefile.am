#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS = vinyllog

vinyllog_SOURCES = \
	vinyllog.c \
	vinyllog_options.h

vinyllog_LDADD = \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}
