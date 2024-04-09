// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>

#include "babel_main.h"
#include "babeld.h"
#include "util.h"
#include "source.h"
#include "babel_interface.h"
#include "route.h"
#include "babel_errors.h"

struct source *srcs = NULL;

struct source*
find_source(const unsigned char *id, const unsigned char *p, unsigned char plen,
            int create, unsigned short seqno)
{
    struct source *src;

    for(src = srcs; src; src = src->next) {
        /* This should really be a hash table.  For now, check the
           last byte first. */
        if(src->id[7] != id[7])
            continue;
        if(memcmp(src->id, id, 8) != 0)
            continue;
        if(src->plen != plen)
            continue;
        if(memcmp(src->prefix, p, 16) == 0)
            return src;
    }

    if(!create)
        return NULL;

    src = malloc(sizeof(struct source));
    if(src == NULL) {
        flog_err(EC_BABEL_MEMORY, "malloc(source): %s", safe_strerror(errno));
        return NULL;
    }

    memcpy(src->id, id, 8);
    memcpy(src->prefix, p, 16);
    src->plen = plen;
    src->seqno = seqno;
    src->metric = INFINITY;
    src->time = babel_now.tv_sec;
    src->route_count = 0;
    src->next = srcs;
    srcs = src;
    return src;
}

struct source *
retain_source(struct source *src)
{
    assert(src->route_count < 0xffff);
    src->route_count++;
    return src;
}

void
release_source(struct source *src)
{
    assert(src->route_count > 0);
    src->route_count--;
}

int
flush_source(struct source *src)
{
    if(src->route_count > 0)
        /* The source is in use by a route. */
        return 0;

    if(srcs == src) {
        srcs = src->next;
    } else {
        struct source *previous = srcs;
        while(previous->next != src)
            previous = previous->next;
        previous->next = src->next;
    }

    free(src);
    return 1;
}

void
update_source(struct source *src,
              unsigned short seqno, unsigned short metric)
{
    if(metric >= INFINITY)
        return;

    /* If a source is expired, pretend that it doesn't exist and update
       it unconditionally.  This makes ensures that old data will
       eventually be overridden, and prevents us from getting stuck if
       a router loses its sequence number. */
    if(src->time < babel_now.tv_sec - SOURCE_GC_TIME ||
       seqno_compare(src->seqno, seqno) < 0 ||
       (src->seqno == seqno && src->metric > metric)) {
        src->seqno = seqno;
        src->metric = metric;
    }
    src->time = babel_now.tv_sec;
}

void
expire_sources(void)
{
    struct source *src;

    src = srcs;
    while(src) {
        if(src->time > babel_now.tv_sec)
            /* clock stepped */
            src->time = babel_now.tv_sec;
        if(src->time < babel_now.tv_sec - SOURCE_GC_TIME) {
            struct source *old = src;
            src = src->next;
            flush_source(old);
            continue;
        }
        src = src->next;
    }
}

void
check_sources_released(void)
{
    struct source *src;

    for(src = srcs; src; src = src->next) {
        if(src->route_count != 0)
            fprintf(stderr, "Warning: source %s %s has refcount %d.\n",
                    format_eui64(src->id),
                    format_prefix(src->prefix, src->plen),
                    (int)src->route_count);
    }
}
