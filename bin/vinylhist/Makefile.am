#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@CURSES_CFLAGS@

bin_PROGRAMS = varnishhist

varnishhist_SOURCES = \
	vinylhist.c \
	vinylhist_options.h \
	vinylhist_profiles.h

varnishhist_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvarnishapi.la \
	-lm @CURSES_LIBS@ ${RT_LIBS} ${PTHREAD_LIBS}
