#!/bin/sh
#
# Copyright (c) 2006-2021 Varnish Software AS
# SPDX-License-Identifier: BSD-2-Clause
# See LICENSE file for full text of license

set -e

CLOPS='
	-I../../lib/libvgz
	-I../../lib/libvsc
	-DNOT_IN_A_VMOD
	-DVDPIO_TEST_DRIVER
	cache/cache_ws.c
	cache/cache_ws_common.c
	cache/cache_deliver_proc.c
	vdpio_test_flint.lnt
'

FLOPS="${CLOPS}"'
	-DVDPIO_MAIN_TEST_DRIVER
	cache/cache_vdpio_mock.c
' ../../tools/flint_skel.sh $*

for f in cache/cache_gzip.c ; do
	FLOPS="${CLOPS} ${f}" \
	../../tools/flint_skel.sh $*
done
