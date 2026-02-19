#

DISTCLEANFILES = builtin.vcl

dist_doc_DATA = builtin.vcl \
		example.vcl

builtin.vcl:	$(top_srcdir)/bin/varnishd/builtin.vcl
	( printf "This is the VCL configuration Varnish will automatically append to your VCL\nfile during compilation/loading. See the vcl(7) man page for details on syntax\nand semantics.\n\
New users is recommended to use the example.vcl file as a starting point.\n\n";\
	sed -n '/vcl_recv/,$$p' $(top_srcdir)/bin/varnishd/builtin.vcl ) | \
	sed 's/^\(.*\)$$/# \1/' > builtin.vcl

vcldir=$(datarootdir)/$(PACKAGE)/vcl

dist_vcl_DATA = devicedetect.vcl

EXTRA_DIST = \
	ca/bundle/cdnN.example.com.pem \
	ca/bundle/ecc.example.com.pem \
	ca/bundle/example.com.pem \
	ca/bundle/foo.example.com.pem \
	ca/bundle/no-san.example.com.pem \
	ca/bundle/protected.example.com.pem \
	ca/bundle/revoked.example.com.pem \
	ca/bundle/wildcard.example.com.pem \
	ca/dh3072.pem \
	ca/intermediate/private/cdnN.example.com.key.pem \
	ca/intermediate/private/client01.key.pem \
	ca/intermediate/private/ecc.example.com.key.pem \
	ca/intermediate/private/example.com.key.pem \
	ca/intermediate/private/foo.example.com.key.pem \
	ca/intermediate/private/intermediate.key.pem \
	ca/intermediate/private/no-san.example.com.pem \
	ca/intermediate/private/ocsp.example.com.key.pem \
	ca/intermediate/private/protected.example.com.key.pem \
	ca/intermediate/private/revoked.example.com.key.pem \
	ca/intermediate/private/testclient.key.pem \
	ca/intermediate/private/wildcard.example.com.key.pem \
	ca/intermediate/certs/cdnN.example.com.cert.pem \
	ca/intermediate/certs/ecc.example.com.cert.pem \
	ca/intermediate/certs/example.com.cert.pem \
	ca/intermediate/certs/foo.example.com.cert.pem \
	ca/intermediate/certs/no-san.example.com.cert.pem \
	ca/intermediate/certs/ocsp.example.com.cert.pem \
	ca/intermediate/certs/protected.example.com.cert.pem \
	ca/intermediate/certs/revoked.example.com.cert.pem \
	ca/intermediate/certs/wildcard.example.com.cert.pem \
	ca/intermediate/private/no-san.example.com.pem

