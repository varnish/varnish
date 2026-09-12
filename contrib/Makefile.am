#

include $(top_srcdir)/vtc.am

scripts = \
	varnishstatdiff \
	vcacheize

if !WITH_CONTRIB
dist_noinst_SCRIPTS = \
	$(scripts)
else
dist_bin_SCRIPTS = \
	$(scripts)

TESTS = @CONTRIB_TESTS@

endif

EXTRA_DIST = @CONTRIB_TESTS@
