#include <stddef.h>
#include "lib/libfrr.h"
#include "pimd/pim_igmp.h"
#include "pimd/pim_igmpv3.h"
#include "pimd/pimd.h"
#include "lib/frr_zmq.h"
#include "hook.h"
#include "module.h"
#include "lib/frrstr.h"
#include "lib/vector.h"
#include "lib/json.h"

static void *zmqsock;

static int pimd_igmpv3_add(struct igmp_group *group, struct in_addr src_addr)
{
	char g[16], s[16];
	struct json_object *out = json_object_new_object();
	char *jsonOut;

	inet_ntop(AF_INET, &group->group_addr.s_addr, g, 15);
	inet_ntop(AF_INET, &src_addr, s, 15);

	json_object_string_add(out, "action", "add");
	json_object_string_add(out, "group", g);
	json_object_string_add(out, "source", s);

	jsonOut = XSTRDUP(MTYPE_TMP, json_object_to_json_string_ext(
					     out, JSON_C_TO_STRING_PRETTY));
	zmq_send(zmqsock, jsonOut, strlen(jsonOut) + 1, 0);
	XFREE(MTYPE_TMP, jsonOut);
	json_object_free(out);

	return 0;
}

static int pimd_igmpv3_del(struct igmp_group *group, struct in_addr src_addr)
{
	char g[16], s[16];
	struct json_object *out = json_object_new_object();
	char *jsonOut;

	inet_ntop(AF_INET, &group->group_addr.s_addr, g, 15);
	inet_ntop(AF_INET, &src_addr, s, 15);

	json_object_string_add(out, "action", "delete");
	json_object_string_add(out, "group", g);
	json_object_string_add(out, "source", s);

	jsonOut = XSTRDUP(MTYPE_TMP, json_object_to_json_string_ext(
					     out, JSON_C_TO_STRING_PRETTY));
	zmq_send(zmqsock, jsonOut, strlen(jsonOut) + 1, 0);
	XFREE(MTYPE_TMP, jsonOut);
	json_object_free(out);

	return 0;
}

static int zmqw_late_init(struct thread_master *tm)
{
	const char *format = THIS_MODULE->load_args;
/* c doesn't like initializers on dynamic length stack variables */
#define ZMQCONNECTSTRLEN 14
	char zmqConnectStr[ZMQCONNECTSTRLEN] = {
		0,
	}; /* tcp:XX*:65536 */
	vector formatVector = frrstr_split_vec(format, ";");

	for (size_t x = 0; x < vector_active(formatVector); x++) {
		vector parameterVector =
			frrstr_split_vec(vector_lookup(formatVector, x), "=");
		char *parameter = vector_lookup(parameterVector, 0);
		if (strcmp(parameter, "port") == 0) {
			snprintf(zmqConnectStr, ZMQCONNECTSTRLEN, "tcp://*:%s",
				 (char *)vector_lookup(parameterVector, 1));
		}
	}

	vector_free(formatVector);

	if (*zmqConnectStr == '\0') {
		zlog_err(
			"could not parse the zmq port number off the command line.  please specify one.  will not initialize the hooks without it\n");
		return -1;
	}

	/* we need to initialize up the zmq library */
	frrzmq_init();

	zmqsock = zmq_socket(frrzmq_context, ZMQ_PUB);
	if (zmq_bind(zmqsock, zmqConnectStr)) {
		perror("zmq_bind() failed!");
		exit(1);
	}

	hook_register(pimd_igmpv3_add, pimd_igmpv3_add);
	hook_register(pimd_igmpv3_del, pimd_igmpv3_del);

	return 0;
}

static int zmqw_init(void)
{
	hook_register(frr_late_init, zmqw_late_init);
	return 0;
}

FRR_MODULE_SETUP(.name = "zmqw", .version = "zmqw", .description = "zmqw",
		 .init = zmqw_init, )
