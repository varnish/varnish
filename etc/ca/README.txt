This is a set of CA, intermediate and subject certificates, for testing purposes.

This has been created using [1] as a reference.

The bundle/ subdirectory contains sample certificate bundles,

example.com.pem
SubjAltNames:
	- DNS:example.com
	- DNS:www.example.com
	- IP:1.2.3.4

cdnN.example.com.pem
SubjAltNames:
	- DNS:cdn01.example.com
	- DNS:cdn02.example.com
	- DNS:cdn03.example.com

wildcard.example.com.pem
SubjAltNames:
	- DNS:wildcard.example.com
	- DNS:*.wildcard.example.com

no-san.example.com.pem
	No SubjAltNames
	CN = no-san.example.com

protected.example.com.pem (password protected, pass = 'foobar')
CN = protected.example.com
SubjAltNames:
	- DNS:protected.example.com

foo.example.com.pem
SubjAltnames:
	- DNS:example.com
	- DNS:foo.example.com
	- DNS:bar.example.com

Each file is a concatenation of subject cert, intermediate cert and
priv key, ready to be loaded by varnishtest/hitch/VCP/whatever.

The root CA certificate is in certs/ca.cert.pem, and needs to be
loaded as SSL_CERT_FILE for valid certificate verification.

[1]: https://jamielinux.com/docs/openssl-certificate-authority/introduction.html
