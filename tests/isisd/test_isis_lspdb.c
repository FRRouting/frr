#include <zebra.h>

#include "isisd/isis_lsp.c"

struct thread_master *master;

int isis_sock_init(struct isis_circuit *circuit);
int isis_sock_init(struct isis_circuit *circuit)
{
	return 0;
}

struct zebra_privs_t isisd_privs;

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

	dict_t *lspdb = lsp_db_init();

	struct isis_lsp *lsp1 = lsp_new(area, lsp_id1, 6000, 0, 0, 0, NULL,
					ISIS_LEVEL2);

	lsp_insert(lsp1, lspdb);

	struct isis_lsp *lsp2 = lsp_new(area, lsp_id2, 6000, 0, 0, 0, NULL,
					ISIS_LEVEL2);

	lsp_insert(lsp2, lspdb);

	struct list *list = list_new();

	lsp_build_list_nonzero_ht(lsp_id1, lsp_id_end, list, lspdb);
	assert(list->count == 1);
	assert(listgetdata(listhead(list)) == lsp1);
	list_delete_all_node(list);

	lsp_id_end[5] = 0x03;
	lsp_id_end[6] = 0x00;

	lsp_build_list_nonzero_ht(lsp_id1, lsp_id_end, list, lspdb);
	assert(list->count == 2);
	assert(listgetdata(listhead(list)) == lsp1);
	assert(listgetdata(listtail(list)) == lsp2);
	list_delete_all_node(list);

	memcpy(lsp_id1, lsp_id2, sizeof(lsp_id1));

	lsp_build_list_nonzero_ht(lsp_id1, lsp_id_end, list, lspdb);
	assert(list->count == 1);
	assert(listgetdata(listhead(list)) == lsp2);
	list_delete_all_node(list);

	lsp_id1[5] = 0x03;
	lsp_id_end[5] = 0x04;

	lsp_build_list_nonzero_ht(lsp_id1, lsp_id_end, list, lspdb);
	assert(list->count == 0);
	list_delete_all_node(list);

	lsp_id1[5] = 0x00;

	lsp_build_list_nonzero_ht(lsp_id1, lsp_id_end, list, lspdb);
	assert(list->count == 2);
	assert(listgetdata(listhead(list)) == lsp1);
	assert(listgetdata(listtail(list)) == lsp2);
	list_delete_all_node(list);
}

int main(int argc, char **argv)
{
	isis = calloc(sizeof(*isis), 1);
	test_lsp_build_list_nonzero_ht();
	return 0;
}
