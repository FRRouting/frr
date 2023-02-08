// SPDX-License-Identifier: MIT
/*
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#ifndef BABELD_BABEL_FILTER_H
#define BABELD_BABEL_FILTER_H

#include <zebra.h>
#include "prefix.h"
#include "babel_interface.h"

int babel_filter(int output, const unsigned char *prefix, unsigned short plen,
                 unsigned int index);

#endif /* BABELD_BABEL_FILTER_H */
