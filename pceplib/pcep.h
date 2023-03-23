// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Javier Garcia <javier.garcia@voltanet.io>
 *
 */


#ifndef PCEP_H_
#define PCEP_H_
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(linux) || defined(GNU_LINUX)

#define ipv6_u __in6_u
#else
/* bsd family */
#define ipv6_u __u6_addr
#ifdef __FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif /* __FreeBSD__ */
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

/* Cross-compilation seems to have trouble finding this */
#if defined(TCP_MD5SIG_MAXKEYLEN)
#define PCEP_MD5SIG_MAXKEYLEN TCP_MD5SIG_MAXKEYLEN
#else
#define PCEP_MD5SIG_MAXKEYLEN 80
#endif

#endif
