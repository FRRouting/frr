#include <zebra.h>

#include "isisd/isis_spf.c"

struct thread_master *master;
int isis_sock_init(struct isis_circuit *circuit);
int isis_sock_init(struct isis_circuit *circuit)
{
	return 0;
}

struct zebra_privs_t isisd_privs;

static struct isis_vertex **vertices;
static size_t vertex_count;

static void setup_test_vertices(void)
{
	union isis_N nid, nip = {
		.prefix.family = AF_UNSPEC
	};

	vertices = XMALLOC(MTYPE_TMP, sizeof(*vertices) * 16);

	nip.prefix.family = AF_INET;
	nip.prefix.prefixlen = 24;
	inet_pton(AF_INET, "192.168.1.0", &nip.prefix.u.prefix4);
	vertices[vertex_count] = isis_vertex_new(&nip, VTYPE_IPREACH_TE);
	vertices[vertex_count]->d_N = 20;
	vertex_count++;

	nip.prefix.family = AF_INET;
	nip.prefix.prefixlen = 24;
	inet_pton(AF_INET, "192.168.2.0", &nip.prefix.u.prefix4);
	vertices[vertex_count] = isis_vertex_new(&nip, VTYPE_IPREACH_TE);
	vertices[vertex_count]->d_N = 20;
	vertex_count++;

	memset(nid.id, 0, sizeof(nid.id));
	nid.id[6] = 1;
	vertices[vertex_count] = isis_vertex_new(&nid, VTYPE_PSEUDO_TE_IS);
	vertices[vertex_count]->d_N = 15;
	vertex_count++;

	memset(nid.id, 0, sizeof(nid.id));
	nid.id[5] = 2;
	vertices[vertex_count] = isis_vertex_new(&nid, VTYPE_NONPSEUDO_TE_IS);
	vertices[vertex_count]->d_N = 15;
	vertex_count++;

	nip.prefix.family = AF_INET;
	nip.prefix.prefixlen = 24;
	inet_pton(AF_INET, "192.168.3.0", &nip.prefix.u.prefix4);
	vertices[vertex_count] = isis_vertex_new(&nip, VTYPE_IPREACH_TE);
	vertices[vertex_count]->d_N = 20;
	vertex_count++;
};

static void cleanup_test_vertices(void)
{
	for (size_t i = 0; i < vertex_count; i++)
		isis_vertex_del(vertices[i]);
	XFREE(MTYPE_TMP, vertices);
	vertex_count = 0;
}

static void test_ordered(void)
{
	struct isis_vertex_queue q;

	isis_vertex_queue_init(&q, NULL, true);
	for (size_t i = 0; i < vertex_count; i++)
		isis_vertex_queue_insert(&q, vertices[i]);

	assert(isis_vertex_queue_count(&q) == vertex_count);

	for (size_t i = 0; i < vertex_count; i++) {
		assert(isis_find_vertex(&q, &vertices[i]->N, vertices[i]->type) == vertices[i]);
	}

	assert(isis_vertex_queue_pop(&q) == vertices[2]);
	assert(isis_find_vertex(&q, &vertices[2]->N, vertices[2]->type) == NULL);

	assert(isis_vertex_queue_pop(&q) == vertices[3]);
	assert(isis_find_vertex(&q, &vertices[3]->N, vertices[3]->type) == NULL);

	assert(isis_vertex_queue_pop(&q) == vertices[0]);
	assert(isis_find_vertex(&q, &vertices[0]->N, vertices[0]->type) == NULL);

	assert(isis_vertex_queue_pop(&q) == vertices[1]);
	assert(isis_find_vertex(&q, &vertices[1]->N, vertices[1]->type) == NULL);

	isis_vertex_queue_delete(&q, vertices[4]);
	assert(isis_find_vertex(&q, &vertices[4]->N, vertices[4]->type) == NULL);

	assert(isis_vertex_queue_count(&q) == 0);
	assert(isis_vertex_queue_pop(&q) == NULL);

	isis_vertex_queue_free(&q);
}

int main(int argc, char **argv)
{
	setup_test_vertices();
	test_ordered();
	cleanup_test_vertices();

	return 0;
}
