#

dist_man_MANS = \
	varnish-cli.7 \
	varnish-counters.7 \
	vcl.7 \
	vcl-backend.7 \
	vcl-probe.7 \
	vcl-var.7 \
	vcl-step.7 \
	vsl.7 \
	vsl-query.7 \
	varnishadm.1 \
	varnishd.1 \
	varnishhist.1 \
	varnishlog.1 \
	varnishncsa.1 \
	varnishstat.1 \
	varnishtest.1 \
	vtc.7 \
	varnishtop.1 \
	vmod_cookie.3 \
	vmod_directors.3 \
	vmod_purge.3 \
	vmod_std.3 \
	vmod_vtc.3 \
	vmod_blob.3 \
	vmod_unix.3 \
	vmod_proxy.3 \
	vmod_h2.3 \
	vmod_math.3

CLEANFILES = $(dist_man_MANS)

RST2ANY_FLAGS = --halt=2

BUILD_MAN = $(AM_V_GEN) $(RST2MAN) $(RST2ANY_FLAGS)

# NB: everything happens in $(builddir) on purpose, even though some
#     RST files are always present in $(srcdir). Links from $(builddir)
#     to $(srcdir) are created for sphinx builds that don't support
#     VPATH.

varnish-cli.7: $(top_builddir)/doc/sphinx/reference/vinyl-cli.rst \
	$(top_builddir)/doc/sphinx/include/cli.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinyl-cli.rst $@

varnish-counters.7: $(top_builddir)/doc/sphinx/reference/vinyl-counters.rst \
	$(top_builddir)/doc/sphinx/include/counters.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinyl-counters.rst $@

vcl.7: $(top_builddir)/doc/sphinx/reference/vcl.rst \
	$(top_builddir)/doc/sphinx/reference/vcl_var.rst \
	$(top_srcdir)/bin/vinyld/builtin.vcl
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vcl.rst $@

vcl-backend.7: $(top_builddir)/doc/sphinx/reference/vcl-backend.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vcl-backend.rst $@

vcl-probe.7: $(top_builddir)/doc/sphinx/reference/vcl-probe.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vcl-probe.rst $@

vcl-var.7: $(top_builddir)/doc/sphinx/reference/vcl-var.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vcl-var.rst $@

vcl-step.7: $(top_builddir)/doc/sphinx/reference/vcl-step.rst \
	$(top_builddir)/doc/sphinx/reference/vcl_step.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vcl-step.rst $@

vsl.7: $(top_builddir)/doc/sphinx/reference/vsl.rst \
	$(top_builddir)/doc/sphinx/include/vsl-tags.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vsl.rst $@

vsl-query.7: $(top_builddir)/doc/sphinx/reference/vsl-query.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vsl-query.rst $@

varnishadm.1: $(top_builddir)/doc/sphinx/reference/vinyladm.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinyladm.rst $@

varnishd.1: \
	$(top_builddir)/doc/sphinx/reference/vinyld.rst \
	$(top_builddir)/doc/sphinx/include/params.rst \
	$(top_builddir)/doc/sphinx/include/options.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinyld.rst $@

varnishncsa.1: \
	$(top_builddir)/doc/sphinx/reference/vinylncsa.rst \
	$(top_builddir)/doc/sphinx/include/varnishncsa_options.rst \
	$(top_builddir)/doc/sphinx/include/varnishncsa_synopsis.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinylncsa.rst $@

varnishlog.1: \
	$(top_builddir)/doc/sphinx/reference/vinyllog.rst \
	$(top_builddir)/doc/sphinx/include/varnishlog_options.rst \
	$(top_builddir)/doc/sphinx/include/varnishlog_synopsis.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinyllog.rst $@

varnishstat.1: $(top_builddir)/doc/sphinx/reference/vinylstat.rst \
	$(top_builddir)/doc/sphinx/include/varnishstat_options.rst \
	$(top_builddir)/doc/sphinx/include/varnishstat_synopsis.rst \
	$(top_builddir)/doc/sphinx/include/varnishstat_bindings.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinylstat.rst $@

varnishtest.1: $(top_builddir)/doc/sphinx/reference/vinyltest.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinyltest.rst $@

vtc.7: $(top_builddir)/doc/sphinx/reference/vtc.rst \
	$(top_builddir)/doc/sphinx/include/vtc-syntax.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vtc.rst $@

varnishtop.1: \
	$(top_builddir)/doc/sphinx/reference/vinyltop.rst \
	$(top_builddir)/doc/sphinx/include/varnishtop_options.rst \
	$(top_builddir)/doc/sphinx/include/varnishtop_synopsis.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinyltop.rst $@

varnishhist.1: \
	$(top_builddir)/doc/sphinx/reference/vinylhist.rst \
	$(top_builddir)/doc/sphinx/include/varnishhist_options.rst \
	$(top_builddir)/doc/sphinx/include/varnishhist_synopsis.rst
	$(BUILD_MAN) $(top_builddir)/doc/sphinx/reference/vinylhist.rst $@

vmod_cookie.3: $(top_builddir)/vmod/vmod_cookie.man.rst
	$(BUILD_MAN) $? $@

vmod_directors.3: $(top_builddir)/vmod/vmod_directors.man.rst
	$(BUILD_MAN) $? $@

vmod_purge.3: $(top_builddir)/vmod/vmod_purge.man.rst
	$(BUILD_MAN) $? $@

vmod_std.3: $(top_builddir)/vmod/vmod_std.man.rst
	$(BUILD_MAN) $? $@

vmod_vtc.3: $(top_builddir)/vmod/vmod_vtc.man.rst
	$(BUILD_MAN) $? $@

vmod_blob.3: $(top_builddir)/vmod/vmod_blob.man.rst
	$(BUILD_MAN) $? $@

vmod_unix.3: $(top_builddir)/vmod/vmod_unix.man.rst
	$(BUILD_MAN) $? $@

vmod_proxy.3: $(top_builddir)/vmod/vmod_proxy.man.rst
	$(BUILD_MAN) $? $@

vmod_h2.3: $(top_builddir)/vmod/vmod_h2.man.rst
	$(BUILD_MAN) $? $@

vmod_math.3: $(top_builddir)/vmod/vmod_math.man.rst
	$(BUILD_MAN) $? $@


.NOPATH: $(dist_man_MANS)
