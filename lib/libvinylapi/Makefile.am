#

AM_LDFLAGS  = $(AM_LT_LDFLAGS)

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include

lib_LTLIBRARIES = libvinylapi.la

libvinylapi_la_LDFLAGS = $(AM_LDFLAGS) -version-info 4:0:1

libvinylapi_la_SOURCES = \
	../../include/vcs_version.h \
	vsl_api.h \
	vxp.h \
	vxp_tokens.h \
	vsc.c \
	vsig.c \
	vsl.c \
	vsl_arg.c \
	vsl_cursor.c \
	vsl_dispatch.c \
	vsl_query.c \
	vsm.c \
	vut.c \
	vxp.c \
	vxp_fixed_token.c \
	vxp_lexer.c \
	vxp_parse.c \
	libvinylapi.map

if ! HAVE_DAEMON
libvinylapi_la_SOURCES += daemon.c
endif

libvinylapi_la_CFLAGS = \
	-DVINYL_STATE_DIR='"${VINYL_STATE_DIR}"'

libvinylapi_la_LIBADD = \
	$(top_builddir)/lib/libvinyl/libvinyl.la \
	${NET_LIBS} ${RT_LIBS} ${LIBM}

if HAVE_LD_VERSION_SCRIPT
libvinylapi_la_LDFLAGS += -Wl,--version-script=$(srcdir)/libvinylapi.map
else
libvinylapi_la_LDFLAGS += -export-symbols-regex '^V'
endif

EXTRA_DIST = \
	generate.py

BUILT_SOURCES = \
	vxp_fixed_token.c \
	vxp_tokens.h

CLEANFILES = \
	$(builddir)/vxp_fixed_token.c \
	$(builddir)/vxp_tokens.h

noinst_PROGRAMS = vsl2rst

vsl2rst_SOURCES = \
	vsl2rst.c \
	$(top_srcdir)/include/tbl/vsl_tags.h \
	$(top_srcdir)/include/tbl/vsl_tags_http.h

vxp_fixed_token.c: vxp_tokens.h

vxp_tokens.h: \
	$(srcdir)/generate.py
	@PYTHON@ $(srcdir)/generate.py $(srcdir) $(top_builddir)

noinst_PROGRAMS += vxp_test

vxp_test_SOURCES = \
	$(libvinylapi_la_SOURCES) \
	vxp_test.c
vxp_test_CFLAGS = \
	-DVINYL_STATE_DIR='"${VINYL_STATE_DIR}"' \
	-DVXP_DEBUG
vxp_test_LDADD = \
	$(top_builddir)/lib/libvinyl/libvinyl.la \
	${RT_LIBS} ${LIBM} ${PTHREAD_LIBS}

noinst_PROGRAMS += vsl_glob_test

vsl_glob_test_SOURCES = vsl_glob_test.c
vsl_glob_test_LDADD = libvinylapi.la

dist_noinst_SCRIPTS = vsl_glob_test_coverage.sh vxp_test_coverage.sh

TESTS = vsl_glob_test_coverage.sh vxp_test_coverage.sh
TEST_EXTENSIONS = .sh
