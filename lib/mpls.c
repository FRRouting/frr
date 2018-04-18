/*
 * mpls functions
 *
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include <mpls.h>
#include <memory.h>

/*
 * String to label conversion, labels separated by '/'.
 *
 * @param label_str labels separated by /
 * @param num_labels number of labels; zero if conversion was unsuccessful
 * @param labels preallocated mpls_label_t array of size MPLS_MAX_LABELS; only
 *               modified if the conversion succeeded
 * @return  0 on success
 *         -1 if the string could not be parsed as integers
 *         -2 if a label was inside the reserved range (0-15)
 *         -3 if the number of labels given exceeds MPLS_MAX_LABELS
 */
int mpls_str2label(const char *label_str, uint8_t *num_labels,
		   mpls_label_t *labels)
{
	char *ostr;			  // copy of label string (start)
	char *lstr;			  // copy of label string
	char *nump;			  // pointer to next segment
	char *endp;			  // end pointer
	int i;				  // for iterating label_str
	int rc;				  // return code
	mpls_label_t pl[MPLS_MAX_LABELS]; // parsed labels

	/* labels to zero until we have a successful parse */
	ostr = lstr = XSTRDUP(MTYPE_TMP, label_str);
	*num_labels = 0;
	rc = 0;

	for (i = 0; i < MPLS_MAX_LABELS && lstr && !rc; i++) {
		nump = strsep(&lstr, "/");
		pl[i] = strtoul(nump, &endp, 10);

		/* format check */
		if (*endp != '\0')
			rc = -1;
		/* validity check */
		else if (!IS_MPLS_UNRESERVED_LABEL(pl[i]))
			rc = -2;
	}

	/* excess labels */
	if (!rc && i == MPLS_MAX_LABELS && lstr)
		rc = -3;

	if (!rc) {
		*num_labels = i;
		memcpy(labels, pl, *num_labels * sizeof(mpls_label_t));
	}

	XFREE(MTYPE_TMP, ostr);

	return rc;
}

/*
 * Label to string conversion, labels in string separated by '/'.
 */
char *mpls_label2str(uint8_t num_labels, mpls_label_t *labels, char *buf,
		     int len, int pretty)
{
	char label_buf[BUFSIZ];
	int i;

	buf[0] = '\0';
	for (i = 0; i < num_labels; i++) {
		if (i != 0)
			strlcat(buf, "/", len);
		if (pretty)
			label2str(labels[i], label_buf, sizeof(label_buf));
		else
			snprintf(label_buf, sizeof(label_buf), "%u", labels[i]);
		strlcat(buf, label_buf, len);
	}

	return buf;
}
