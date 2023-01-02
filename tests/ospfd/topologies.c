#include <zebra.h>

#include "mpls.h"
#include "if.h"

#include "ospfd/ospfd.h"

#include "common.h"

/*
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |eth-rt2       eth-rt1|   RT2   |
 * | 1.1.1.1 +---------------------+ 2.2.2.2 |
 * |         |     10.0.1.0/24     |         |
 * +---------+                     +---------+
 *      |eth-rt3                 eth-rt3|
 *      |                               |
 *      |10.0.3.0/24                    |
 *      |                               |
 *      |eth-rt1                        |
 * +---------+                          |
 * |         |eth-rt2        10.0.2.0/24|
 * |   RT3   +--------------------------+
 * | 3.3.3.3 |
 * |         |
 * +---------+
 *
 * Link Protection:
 * P and Q spaces overlap here, hence just one P/Q node regardless of which
 * link is protected. Hence the backup label stack just has one label.
 *
 * Node Protection:
 * Obviously no backup paths involved.
 */
struct ospf_topology topo1 = {
	.nodes =
		{
			{
				.hostname = "rt1",
				.router_id = "1.1.1.1",
				.label = 10,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.1.1/24",
							.metric = 10,
							.label = 1,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.3.1/24",
							.metric = 10,
							.label = 2,
						},
					},
			},
			{
				.hostname = "rt2",
				.router_id = "2.2.2.2",
				.label = 20,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.1.2/24",
							.metric = 10,
							.label = 3,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.2.1/24",
							.metric = 10,
							.label = 4,
						},
					},
			},
			{
				.hostname = "rt3",
				.router_id = "3.3.3.3",
				.label = 30,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.3.2/24",
							.metric = 10,
							.label = 5,
						},
						{
							.hostname = "rt2",
							.network =
								"10.0.2.2/24",
							.metric = 10,
							.label = 6,
						},
					},
			},
		},
};


/*
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |eth-rt2       eth-rt1|   RT2   |
 * | 1.1.1.1 +---------------------+ 2.2.2.2 |
 * |         |  10.0.1.0/24 (10)   |         |
 * +---------+                     +---------+
 *      |eth-rt3                 eth-rt3|
 *      |                               |
 *      |10.0.3.0/24 (30)               |
 *      |                               |
 *      |eth-rt1                        |
 * +---------+                          |
 * |         |eth-rt2        10.0.2.0/24|(10)
 * |   RT3   +--------------------------+
 * | 3.3.3.3 |
 * |         |
 * +---------+
 *
 * Link Protection:
 * Regarding the subnet 10.0.1.0/24, the P space of RT1 is just RT1 itself
 * while the Q space of RT3 consists of RT3 and RT2. Hence the P and Q
 * nodes are disjunct (tricky: the root node is the P node here). For the
 * backup label stack just one label is necessary.
 *
 * Node Protection:
 * For protected node RT2 and route from RT1 to RT3 there is just the backup
 * path consisting of the label 15002.
 */
struct ospf_topology topo2 = {
	.nodes =
		{
			{
				.hostname = "rt1",
				.router_id = "1.1.1.1",
				.label = 10,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.1.1/24",
							.metric = 10,
							.label = 1,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.3.1/24",
							.metric = 30,
							.label = 2,
						},
					},
			},
			{
				.hostname = "rt2",
				.router_id = "2.2.2.2",
				.label = 20,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.1.2/24",
							.metric = 10,
							.label = 3,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.2.1/24",
							.metric = 10,
							.label = 4,
						},
					},
			},
			{
				.hostname = "rt3",
				.router_id = "3.3.3.3",
				.label = 30,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.3.2/24",
							.metric = 30,
							.label = 5,
						},
						{
							.hostname = "rt2",
							.network =
								"10.0.2.2/24",
							.metric = 10,
							.label = 6,
						},
					},
			},
		},
};

/*
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |eth-rt4       eth-rt1|   RT4   |
 * | 1.1.1.1 +---------------------+ 4.4.4.4 |
 * |         |  10.0.4.0/24 (10)   |         |
 * +---------+                     +---------+
 *      |eth-rt2                 eth-rt3|
 *      |                               |
 *      |10.0.1.0/24 (10)               |
 *      |              10.0.3.0/24 (10) |
 *      |eth-rt1                 eth-rt4|
 * +---------+                     +---------+
 * |         |eth-rt3       eth-rt2|         |
 * |   RT2   +---------------------+   RT3   |
 * | 2.2.2.2 |  10.0.2.0/24 (20)   | 3.3.3.3 |
 * |         |                     |         |
 * +---------+                     +---------+
 *
 * Link Protection:
 * Regarding the protected subnet 10.0.4.0/24, the P and Q spaces for root RT1
 * and destination RT4 are disjunct and the P node is RT2 while RT3 is the Q
 * node. Hence the backup label stack here is 16020/15004. Note that here the
 * P and Q nodes are neither the root nor the destination nodes, so this is a
 * case where you really need a label stack consisting of two labels.
 *
 * Node Protection:
 * For the protected node RT4 and the route from RT1 to RT3 there is a backup
 * path with the single label 15001.
 */
struct ospf_topology topo3 = {
	.nodes =
		{
			{
				.hostname = "rt1",
				.router_id = "1.1.1.1",
				.label = 10,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.1.1/24",
							.metric = 10,
							.label = 1,
						},
						{
							.hostname = "rt4",
							.network =
								"10.0.4.1/24",
							.metric = 10,
							.label = 2,
						},
					},
			},
			{
				.hostname = "rt2",
				.router_id = "2.2.2.2",
				.label = 20,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.1.2/24",
							.metric = 10,
							.label = 3,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.2.1/24",
							.metric = 20,
							.label = 4,
						},
					},
			},
			{
				.hostname = "rt3",
				.router_id = "3.3.3.3",
				.label = 30,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.2.2/24",
							.metric = 20,
							.label = 5,
						},
						{
							.hostname = "rt4",
							.network =
								"10.0.3.1/24",
							.metric = 10,
							.label = 6,
						},
					},
			},
			{
				.hostname = "rt4",
				.router_id = "4.4.4.4",
				.label = 40,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.4.2/24",
							.metric = 10,
							.label = 7,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.3.2/24",
							.metric = 10,
							.label = 8,
						},
					},
			},
		},
};

/*
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |eth-rt4       eth-rt1|   RT4   |
 * | 1.1.1.1 +---------------------+ 4.4.4.4 |
 * |         |  10.0.4.0/24 (10)   |         |
 * +---------+                     +---------+
 *      |eth+rt2                 eth-rt3|
 *      |                               |
 *      |10.0.1.0/24 (10)               |
 *      |              10.0.3.0/24 (10) |
 *      |eth-rt1                 eth-rt4|
 * +---------+                     +---------+
 * |         |eth-rt3       eth-rt2|         |
 * |   RT2   +---------------------+   RT3   |
 * | 2.2.2.2 |  10.0.2.0/24 (40)   | 3.3.3.3 |
 * |         |                     |         |
 * +---------+                     +---------+
 *
 * This case was specifically created for Node Protection with RT4 as
 * protected node from the perspective of RT1. Note the weight of 40
 * on the link between RT2 and RT3.
 * The P space of RT1 is just RT2 while the Q space of RT3 is empty.
 * This means that the P and Q spaces are disjunct and there are two
 * labels needed to get from RT1 to RT3.
 */
struct ospf_topology topo4 = {
	.nodes =
		{
			{
				.hostname = "rt1",
				.router_id = "1.1.1.1",
				.label = 10,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.1.1/24",
							.metric = 10,
							.label = 1,
						},
						{
							.hostname = "rt4",
							.network =
								"10.0.4.1/24",
							.metric = 10,
							.label = 2,
						},
					},
			},
			{
				.hostname = "rt2",
				.router_id = "2.2.2.2",
				.label = 20,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.1.2/24",
							.metric = 10,
							.label = 3,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.2.1/24",
							.metric = 50,
							.label = 4,
						},
					},
			},
			{
				.hostname = "rt3",
				.router_id = "3.3.3.3",
				.label = 30,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.2.2/24",
							.metric = 50,
							.label = 5,
						},
						{
							.hostname = "rt4",
							.network =
								"10.0.3.1/24",
							.metric = 10,
							.label = 6,
						},
					},
			},
			{
				.hostname = "rt4",
				.router_id = "4.4.4.4",
				.label = 40,
				.adjacencies =
					{
						{
							.hostname = "rt3",
							.network =
								"10.0.3.2/24",
							.metric = 10,
							.label = 7,
						},
						{
							.hostname = "rt1",
							.network =
								"10.0.4.2/24",
							.metric = 10,
							.label = 8,
						},
					},
			},
		},
};

/*
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |eth-rt4       eth-rt1|   RT4   |
 * | 1.1.1.1 +---------------------+ 4.4.4.4 |
 * |         |  10.0.4.0/24        |         |
 * +---------+                     +---------+
 *      |eth+rt2                 eth-rt3|
 *      |                               |
 *      |10.0.1.0/24                    |
 *      |                    10.0.3.0/24|
 *      |eth-rt1                 eth-rt4|
 * +---------+                     +---------+
 * |         |eth-rt3       eth-rt2|         |
 * |   RT2   +---------------------+   RT3   |
 * | 2.2.2.2 |     10.0.2.0/24     | 3.3.3.3 |
 * |         |                     |         |
 * +---------+                     +---------+
 *
 * Weights:
 * - clockwise: 10
 * - counterclockwise: 40
 *
 * This is an example where 3 (!) labels are needed for the protected
 * link RT1<->RT2, e.g. the subnet 10.0.1.0/24, to reach RT4.
 *
 * Because the initial P and Q spaces will not be overlapping or
 * adjacent for this case the TI-LFA will be applied recursively.
 */
struct ospf_topology topo5 = {
	.nodes =
		{
			{
				.hostname = "rt1",
				.router_id = "1.1.1.1",
				.label = 10,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.1.1/24",
							.metric = 40,
							.label = 1,
						},
						{
							.hostname = "rt4",
							.network =
								"10.0.4.1/24",
							.metric = 10,
							.label = 2,
						},
					},
			},
			{
				.hostname = "rt2",
				.router_id = "2.2.2.2",
				.label = 20,
				.adjacencies =
					{
						{
							.hostname = "rt1",
							.network =
								"10.0.1.2/24",
							.metric = 10,
							.label = 3,
						},
						{
							.hostname = "rt3",
							.network =
								"10.0.2.1/24",
							.metric = 40,
							.label = 4,
						},
					},
			},
			{
				.hostname = "rt3",
				.router_id = "3.3.3.3",
				.label = 30,
				.adjacencies =
					{
						{
							.hostname = "rt2",
							.network =
								"10.0.2.2/24",
							.metric = 10,
							.label = 5,
						},
						{
							.hostname = "rt4",
							.network =
								"10.0.3.1/24",
							.metric = 40,
							.label = 6,
						},
					},
			},
			{
				.hostname = "rt4",
				.router_id = "4.4.4.4",
				.label = 40,
				.adjacencies =
					{
						{
							.hostname = "rt3",
							.network =
								"10.0.3.2/24",
							.metric = 10,
							.label = 7,
						},
						{
							.hostname = "rt1",
							.network =
								"10.0.4.2/24",
							.metric = 40,
							.label = 8,
						},
					},
			},
		},
};
