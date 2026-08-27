#!/bin/sh

set -e

#
# Run flexelint on the VCL output
VMODS="$PWD/../../vmod/.libs"

if test "x$1" = "x" ; then
	if ! ./varnishd -p "vmod_path=$VMODS" -C -f "$PWD/vclflint.vcl" 2>"/tmp/_.c" ; then
		cat >&2 "/tmp/_.c"
		exit 1
	fi
elif test -f "$1" ; then
	if ! ./varnishd -p "vmod_path=$VMODS" -C -f "$1" 2>"/tmp/_.c" ; then
		cat >&2 "/tmp/_.c"
		exit 1
	fi
else
	echo "usage!" 1>&2
fi

flexelint vclflint.lnt "/tmp/_.c"
