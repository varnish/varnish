#!/bin/sh

# This is a tiny utility that generates and outputs the digest in the
# same way that is used for file names in Varnish's OCSP caching
# directory.
#

if [ $# != 1 ]; then
    echo "Usage: $0 <certificate.pem>"
    exit 1
fi

f=$(mktemp)
openssl x509 -in $1 -issuer -serial -noout >$f
issuer=$(grep -e '^issuer=' $f)
serial=$(grep -e '^serial=' $f)
serial=$(echo "ibase=16; ${serial#serial=}" | bc)
rm $f

echo -n "${issuer#issuer=}$serial" | sha256sum | awk '{print $1}'

