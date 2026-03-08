#

AM_CPPFLAGS = \
	-I$(top_srcdir)/include \
	-I$(top_builddir)/include \
	@PCRE2_CFLAGS@

AM_CFLAGS   = $(AM_LT_CFLAGS)
AM_LDFLAGS  = $(AM_LT_LDFLAGS)

noinst_LTLIBRARIES = libvinyl.la

libvinyl_la_CFLAGS = \
	-DVINYL_STATE_DIR='"${VINYL_STATE_DIR}"' \
	$(AM_CFLAGS)

libvinyl_la_SOURCES = \
	vbh.c \
	vas.c \
	vav.c \
	vbt.c \
	vcli_proto.c \
	vcli_serve.c \
	vct.c \
	venc.c \
	vefd.c \
	version.c \
	vev.c \
	vfil.c \
	vfl.c \
	vin.c \
	vjsn.c \
	vlu.c \
	vmb.c \
	vnum.c \
	vpf.c \
	vre.c \
	vrnd.c \
	vsa.c \
	vsb.c \
	vsha256.c \
	vss.c \
	vsub.c \
	vtcp.c \
	vte.c \
	vtim.c \
	vus.c

libvinyl_la_LIBADD = @PCRE2_LIBS@ $(LIBM)

if WITH_UNWIND
libvinyl_la_CFLAGS += -DUNW_LOCAL_ONLY $(LIBUNWIND_CFLAGS)
libvinyl_la_LIBADD += $(LIBUNWIND_LIBS)
endif

TESTS = \
	vav_test \
	vbh_test \
	vct_test \
	vjsn_test \
	vnum_c_test \
	vsb_test \
	vte_test \
	vtim_test

noinst_PROGRAMS = ${TESTS}

vav_test_SOURCES = vav.c
vav_test_CFLAGS = $(AM_CFLAGS) -DTEST_DRIVER
vav_test_LDADD = $(AM_LDFLAGS) libvinyl.la

vbh_test_SOURCES	= vbh.c
vbh_test_CFLAGS = $(AM_CFLAGS) -DTEST_DRIVER
vbh_test_LDADD = $(AM_LDFLAGS) libvinyl.la

vct_test_SOURCES	= vct.c
vct_test_CFLAGS = $(AM_CFLAGS) -DTEST_DRIVER
vct_test_LDADD = $(AM_LDFLAGS) libvinyl.la

vnum_c_test_SOURCES = vnum.c
vnum_c_test_CFLAGS = $(AM_CFLAGS) -DNUM_C_TEST
vnum_c_test_LDADD = $(AM_LDFLAGS) libvinyl.la

vjsn_test_SOURCES = vjsn.c
vjsn_test_CFLAGS = $(AM_CFLAGS) -DVJSN_TEST
vjsn_test_LDADD = $(AM_LDFLAGS) libvinyl.la

vsb_test_SOURCES = vsb_test.c
vsb_test_CFLAGS = $(AM_CFLAGS) -DVSB_TEST
vsb_test_LDADD = $(AM_LDFLAGS) libvinyl.la

vte_test_SOURCES = vte.c
vte_test_CFLAGS = $(AM_CFLAGS) -DTEST_DRIVER
vte_test_LDADD = $(AM_LDFLAGS) libvinyl.la

vtim_test_SOURCES = vtim.c
vtim_test_CFLAGS = $(AM_CFLAGS) -DTEST_DRIVER
vtim_test_LDADD = $(AM_LDFLAGS) libvinyl.la
