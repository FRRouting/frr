// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
*/

#ifndef BABEL_SOURCE_H
#define BABEL_SOURCE_H

#define SOURCE_GC_TIME 200

struct source {
    struct source *next;
    unsigned char id[8];
    unsigned char prefix[16];
    unsigned char plen;
    unsigned short seqno;
    unsigned short metric;
    unsigned short route_count;
    time_t time;
};

struct source *find_source(const unsigned char *id,
                           const unsigned char *p,
                           unsigned char plen,
                           int create, unsigned short seqno);
struct source *retain_source(struct source *src);
void release_source(struct source *src);
int flush_source(struct source *src);
void update_source(struct source *src,
                   unsigned short seqno, unsigned short metric);
void expire_sources(void);
void check_sources_released(void);

#endif
