#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@CURSES_CFLAGS@

bin_PROGRAMS = vinyltop

vinyltop_SOURCES = \
	vinyltop.c \
	vinyltop_options.h

vinyltop_LDADD = \
	$(top_builddir)/lib/libvarnishapi/libvarnishapi.la \
	@CURSES_LIBS@ ${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}
