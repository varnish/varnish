#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

bin_PROGRAMS = varnishlog-json

varnishlog_json_SOURCES = \
	varnishlog-json.c \
	varnishlog-json_options.h \
	cJSON.c \
	cJSON.h

varnishlog_json_LDADD = \
	$(top_builddir)/lib/libvinylapi/libvinylapi.la \
	${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}
