#include <zebra.h>

#include "isisd/isis_lsp.c"

#include "test_common.h"

static void test_lsp_build_list_nonzero_ht(void)
{
	uint8_t lsp_id1[8]    = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00
	};
	uint8_t lsp_id_end[8] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x5f, 0x00
	};
	uint8_t lsp_id2[8]    = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00
	};

	struct isis_area *area = calloc(sizeof(*area), 1);

	area->lsp_mtu = 1500;

	struct lspdb_head _lspdb, *lspdb = &_lspdb;
	lsp_db_init(&_lspdb);

	struct isis_lsp *lsp1 =
		lsp_new(area, lsp_id1, 6000, 1, 0, 0, NULL, ISIS_LEVEL2);

	lspdb_add(lspdb, lsp1);

	struct isis_lsp *lsp2 =
		lsp_new(area, lsp_id2, 6000, 1, 0, 0, NULL, ISIS_LEVEL2);

	lspdb_add(lspdb, lsp2);

	struct list *list = list_new();

	lsp_build_list_nonzero_ht(lspdb, lsp_id1, lsp_id_end, list);
	assert(list->count == 1);
	assert(listgetdata(listhead(list)) == lsp1);
	list_delete_all_node(list);

	lsp_id_end[5] = 0x03;
	lsp_id_end[6] = 0x00;

	lsp_build_list_nonzero_ht(lspdb, lsp_id1, lsp_id_end, list);
	assert(list->count == 2);
	assert(listgetdata(listhead(list)) == lsp1);
	assert(listgetdata(listtail(list)) == lsp2);
	list_delete_all_node(list);

	memcpy(lsp_id1, lsp_id2, sizeof(lsp_id1));

	lsp_build_list_nonzero_ht(lspdb, lsp_id1, lsp_id_end, list);
	assert(list->count == 1);
	assert(listgetdata(listhead(list)) == lsp2);
	list_delete_all_node(list);

	lsp_id1[5] = 0x03;
	lsp_id_end[5] = 0x04;

	lsp_build_list_nonzero_ht(lspdb, lsp_id1, lsp_id_end, list);
	assert(list->count == 0);
	list_delete_all_node(list);

	lsp_id1[5] = 0x00;

	lsp_build_list_nonzero_ht(lspdb, lsp_id1, lsp_id_end, list);
	assert(list->count == 2);
	assert(listgetdata(listhead(list)) == lsp1);
	assert(listgetdata(listtail(list)) == lsp2);
	list_delete_all_node(list);
}

int main(int argc, char **argv)
{
	struct isis *isis = NULL;
	isis = calloc(sizeof(*isis), 1);
	test_lsp_build_list_nonzero_ht();
	return 0;
}
