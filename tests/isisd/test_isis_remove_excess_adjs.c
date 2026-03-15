// SPDX-License-Identifier: GPL-2.0-or-later

#include <zebra.h>
#include "frrevent.h"
#include "memory.h"
#include "linklist.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isisd.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_network.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_spf_private.h"

#include "test_common.h"

/* Pull in the static function */
#include "isisd/isis_spf.c"

static struct isis_circuit mock_circuit = { .idx = 1 };

static struct isis_spf_adj *make_sadj(uint8_t sysid_byte)
{
	struct isis_spf_adj *sadj;
	struct isis_adjacency *adj;

	adj = XCALLOC(MTYPE_TMP, sizeof(*adj));
	adj->sys_type = ISIS_SYSTYPE_L2_IS;
	adj->sysid[ISIS_SYS_ID_LEN - 1] = sysid_byte;
	adj->circuit = &mock_circuit;

	sadj = XCALLOC(MTYPE_TMP, sizeof(*sadj));
	sadj->adj = adj;
	return sadj;
}

static void free_sadj(struct isis_spf_adj *sadj)
{
	XFREE(MTYPE_TMP, sadj->adj);
	XFREE(MTYPE_TMP, sadj);
}

static int test_no_leak(void)
{
	struct list *adjs;
	struct isis_spf_adj **sadjs;
	int n = ISIS_MAX_PATH_SPLITS + 1;
	unsigned long alloc_before;

	alloc_before = MTYPE_ISIS_VERTEX_ADJ->n_alloc;

	adjs = list_new();
	adjs->del = isis_vertex_adj_free;

	sadjs = XCALLOC(MTYPE_TMP, n * sizeof(*sadjs));
	for (int i = 0; i < n; i++) {
		struct isis_vertex_adj *vadj;

		sadjs[i] = make_sadj((uint8_t)i);
		vadj = XCALLOC(MTYPE_ISIS_VERTEX_ADJ, sizeof(*vadj));
		vadj->sadj = sadjs[i];
		listnode_add(adjs, vadj);
	}

	/* We allocated n vertex_adjs */
	assert(MTYPE_ISIS_VERTEX_ADJ->n_alloc == alloc_before + n);

	/* remove_excess_adjs removes one from the list */
	remove_excess_adjs(adjs);

	assert(listcount(adjs) == ISIS_MAX_PATH_SPLITS);

	/*
	 * remove_excess_adjs() shall free the removed
	 * vertex_adj, so n_alloc should be (n - 1) above baseline.
	 */
	assert(MTYPE_ISIS_VERTEX_ADJ->n_alloc == alloc_before + (n - 1));

	/* Clean up the remaining ones via the list destructor */
	list_delete(&adjs);

	/* Now everything should be back to baseline */
	assert(MTYPE_ISIS_VERTEX_ADJ->n_alloc == alloc_before);

	/* Clean up mock sadjs */
	for (int i = 0; i < n; i++)
		free_sadj(sadjs[i]);
	XFREE(MTYPE_TMP, sadjs);

	printf("%s: OK\n", __func__);
	return 0;
}

int main(int argc, char **argv)
{
	if (test_no_leak() != 0)
		return 1;

	printf("test_isis_remove_excess_adjs: OK\n");
	return 0;
}
