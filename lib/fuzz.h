/*
 * Utilities for fuzzing frr.
 */
#ifndef __FUZZ_H__
#define __FUZZ_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

static inline int frrfuzz_read_input(uint8_t **input)
{
	fseek(stdin, 0, SEEK_END);
	long fsize = ftell(stdin);
	if (fsize < 0)
		return 0;

	*input = (uint8_t *)malloc(fsize);

	fseek(stdin, 0, SEEK_SET);
	int r = fread(*input, 1, fsize, stdin);

	return r;
}

#endif /* __FUZZ_H__ */
