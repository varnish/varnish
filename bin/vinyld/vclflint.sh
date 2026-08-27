#!/bin/sh

set -e

#
# Run flexelint on the VCL output
LIBS="-p vmod_path=$PWD/../../vmod/.libs"

if [ "x$1" = "x" ] ; then
	if ! ./varnishd $LIBS -C -f $PWD/vclflint.sh 2> /tmp/_.c ; then
		cat >&2 /tmp/_.c
		exit 1
	fi
elif [ -f $1 ] ; then
	if ! ./varnishd $LIBS -C -f $1 2> /tmp/_.c ; then
		cat >&2 /tmp/_.c
		exit 1
	fi
else
	echo "usage!" 1>&2
fi

flexelint vclflint.lnt /tmp/_.c
