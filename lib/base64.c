// SPDX-License-Identifier: NONE
/*
 * This is part of the libb64 project, and has been placed in the public domain.
 * For details, see http://sourceforge.net/projects/libb64
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "base64.h"
#include "compiler.h"

static const int CHARS_PER_LINE = 72;
static const char *ENCODING =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_init_encodestate(struct base64_encodestate *state_in)
{
	state_in->step = step_A;
	state_in->result = 0;
	state_in->stepcount = 0;
}

char base64_encode_value(char value_in)
{
	if (value_in > 63)
		return '=';
	return ENCODING[(int)value_in];
}

int base64_encode_block(const char *plaintext_in, int length_in, char *code_out,
			struct base64_encodestate *state_in)
{
	const char *plainchar = plaintext_in;
	const char *const plaintextend = plaintext_in + length_in;
	char *codechar = code_out;
	char result;
	char fragment;

	result = state_in->result;

	switch (state_in->step) {
		while (1) {
			fallthrough;
			case step_A:
				if (plainchar == plaintextend) {
					state_in->result = result;
					state_in->step = step_A;
					return codechar - code_out;
				}
				fragment = *plainchar++;
				result = (fragment & 0x0fc) >> 2;
				*codechar++ = base64_encode_value(result);
				result = (fragment & 0x003) << 4;
				fallthrough;
			case step_B:
				if (plainchar == plaintextend) {
					state_in->result = result;
					state_in->step = step_B;
					return codechar - code_out;
				}
				fragment = *plainchar++;
				result |= (fragment & 0x0f0) >> 4;
				*codechar++ = base64_encode_value(result);
				result = (fragment & 0x00f) << 2;
				fallthrough;
			case step_C:
				if (plainchar == plaintextend) {
					state_in->result = result;
					state_in->step = step_C;
					return codechar - code_out;
				}
				fragment = *plainchar++;
				result |= (fragment & 0x0c0) >> 6;
				*codechar++ = base64_encode_value(result);
				result  = (fragment & 0x03f) >> 0;
				*codechar++ = base64_encode_value(result);

				++(state_in->stepcount);
				if (state_in->stepcount == CHARS_PER_LINE/4) {
					*codechar++ = '\n';
					state_in->stepcount = 0;
				}
		}
	}
	/* control should not reach here */
	return codechar - code_out;
}

int base64_encode_blockend(char *code_out, struct base64_encodestate *state_in)
{
	char *codechar = code_out;

	switch (state_in->step) {
	case step_B:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		*codechar++ = '=';
		break;
	case step_C:
		*codechar++ = base64_encode_value(state_in->result);
		*codechar++ = '=';
		break;
	case step_A:
		break;
	}
	*codechar++ = '\n';

	return codechar - code_out;
}


signed char base64_decode_value(signed char value_in)
{
	static const signed char decoding[] = {
		62, -1, -1, -1, 63, 52, 53, 54,
		55, 56, 57, 58, 59, 60, 61, -1,
		-1, -1, -2, -1, -1, -1, 0, 1,
		2,  3, 4, 5, 6, 7, 8, 9,
		10, 11, 12, 13, 14, 15, 16, 17,
		18, 19, 20, 21, 22, 23, 24, 25,
		-1, -1, -1, -1, -1, -1, 26, 27,
		28, 29, 30, 31, 32, 33, 34, 35,
		36, 37, 38, 39, 40, 41, 42, 43,
		44, 45, 46, 47, 48, 49, 50, 51
	};
	value_in -= 43;
	if (value_in < 0 || value_in >= 80)
		return -1;
	return decoding[(int)value_in];
}

void base64_init_decodestate(struct base64_decodestate *state_in)
{
	state_in->step = step_a;
	state_in->plainchar = 0;
}

int base64_decode_block(const char *code_in, int length_in, char *plaintext_out,
			struct base64_decodestate *state_in)
{
	const char *codec = code_in;
	char *plainc = plaintext_out;
	signed char fragmt;

	*plainc = state_in->plainchar;

	switch (state_in->step) {
		while (1) {
			fallthrough;
			case step_a:
				do {
					if (codec == code_in+length_in) {
						state_in->step = step_a;
						state_in->plainchar = *plainc;
						return plainc - plaintext_out;
					}
					fragmt = base64_decode_value(*codec++);
				} while (fragmt < 0);
				*plainc = (fragmt & 0x03f) << 2;
				fallthrough;
			case step_b:
				do {
					if (codec == code_in+length_in) {
						state_in->step = step_b;
						state_in->plainchar = *plainc;
						return plainc - plaintext_out;
					}
					fragmt = base64_decode_value(*codec++);
				} while (fragmt < 0);
				*plainc++ |= (fragmt & 0x030) >> 4;
				*plainc = (fragmt & 0x00f) << 4;
				fallthrough;
			case step_c:
				do {
					if (codec == code_in+length_in) {
						state_in->step = step_c;
						state_in->plainchar = *plainc;
						return plainc - plaintext_out;
					}
					fragmt = base64_decode_value(*codec++);
				} while (fragmt < 0);
				*plainc++ |= (fragmt & 0x03c) >> 2;
				*plainc = (fragmt & 0x003) << 6;
				fallthrough;
			case step_d:
				do {
					if (codec == code_in+length_in) {
						state_in->step = step_d;
						state_in->plainchar = *plainc;
						return plainc - plaintext_out;
					}
					fragmt = base64_decode_value(*codec++);
				} while (fragmt < 0);
				*plainc++   |= (fragmt & 0x03f);
		}
	}
	/* control should not reach here */
	return plainc - plaintext_out;
}
