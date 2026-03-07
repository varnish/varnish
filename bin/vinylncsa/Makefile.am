#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS = vinylncsa

vinylncsa_SOURCES = \
	vinylncsa.c \
	vinylncsa_options.h

vinylncsa_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvinylapi.la \
	${RT_LIBS} ${LIBM}
