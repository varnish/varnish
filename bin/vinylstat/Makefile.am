#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@CURSES_CFLAGS@

bin_PROGRAMS = vinylstat vinylstat_help_gen

vinylstat_SOURCES = \
	vinylstat.h \
	vinylstat.c \
	vinylstat_bindings.h \
	vinylstat_curses.c \
	vinylstat_options.h

nodist_vinylstat_SOURCES = \
	vinylstat_curses_help.c

BUILT_SOURCES = $(nodist_vinylstat_SOURCES)
DISTCLEANFILES = $(nodist_vinylstat_SOURCES)

vinylstat_help_gen_SOURCES = \
	vinylstat_help_gen.c \
	vinylstat_bindings.h

vinylstat_curses_help.c: vinylstat_help_gen
	$(AM_V_GEN) ./vinylstat_help_gen >$@_
	@mv $@_ $@

vinylstat_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvinylapi.la \
	@CURSES_LIBS@ ${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}

vinylstat_help_gen_LDADD = \
	$(top_builddir)/lib/libvarnish/libvarnish.la
