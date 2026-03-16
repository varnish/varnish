#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@CURSES_CFLAGS@

bin_PROGRAMS = varnishtop

varnishtop_SOURCES = \
	vinyltop.c \
	vinyltop_options.h

varnishtop_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvarnishapi.la \
	@CURSES_LIBS@ ${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}
