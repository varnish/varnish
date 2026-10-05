#!/bin/sh
#
# Copyright (c) 2008-2021 Varnish Software AS
# SPDX-License-Identifier: BSD-2-Clause
# See LICENSE file for full text of license

FLOPS="
	-DTOP_BUILDDIR="foo"
	-I../../lib/libvgz
	-Ivtest2
	-Ivtest2/lib
	$(ls vtest2/src/*.c| grep -v /teken.)
	vtest_ext_varnish*.c
" ../../tools/flint_skel.sh
