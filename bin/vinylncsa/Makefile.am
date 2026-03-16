#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS = varnishncsa

varnishncsa_SOURCES = \
	vinylncsa.c \
	vinylncsa_options.h

varnishncsa_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvarnishapi.la \
	${RT_LIBS} ${LIBM}
