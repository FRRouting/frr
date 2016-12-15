#!/bin/sh

sed -e '1istatic void bgp_debug_clear_updgrp_update_dbg(struct bgp *bgp);' -i \
	bgpd/bgp_debug.c
sed -e 's%^#if 0%#if 1 /* 0 */%' -i \
	ospfd/ospf_vty.c \
	ospf6d/ospf6_top.c \
	#
spatch \
	--sp-file    tools/vty_index.cocci \
	--macro-file tools/cocci.h \
	--all-includes -I . -I lib \
	--use-gitgrep --dir . --in-place

sed -e 's%^#if 1 /\* 0 \*/%#if 0%' -i \
	ospfd/ospf_vty.c \
	ospf6d/ospf6_top.c \
	#
sed -e '1d' -i \
	bgpd/bgp_debug.c

