#

include $(top_srcdir)/vtc.am

if !WITH_CONTRIB
dist_noinst_SCRIPTS = \
	vinylstatdiff
else
dist_bin_SCRIPTS = \
	vinylstatdiff

TESTS = @CONTRIB_TESTS@

endif

EXTRA_DIST = @CONTRIB_TESTS@
