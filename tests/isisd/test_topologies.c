/*
 * Copyright (C) 2020  NetDEF, Inc.
 *                     Renato Westphal
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

#include "isisd/isisd.h"

#include "test_common.h"

/*
 * clang-format off
 *
 * All topologies have the following properties:
 * - The System-ID is 0000.0000.000X, where X is the node number (in hex);
 * - The Router-ID is 10.0.255.X, where X is the node number;
 * - The default link metric is 10;
 * - When SR is enabled, Adj-SIDs and Prefix-SIDs are generated automatically;
 * - When SR is enabled, the default SRGB is [16000-23999] (can be overridden).
 *
 * Test topology 1:
 * ================
 *
 *                 +---------+
 *                 |         |
 *                 |   RT1   |
 *      +----------+         +----------+
 *      |          |         |          |
 *      |          +---------+          |
 *      |                               |
 *      |                               |
 *      |                               |
 * +----+----+                     +----+----+
 * |         |                     |         |
 * |   RT2   |                     |   RT3   |
 * |         |                     |         |
 * |         |                     |         |
 * +----+----+                     +----+----+
 *      |                               |
 *      |                               |
 *      |                               |
 * +---+-+---+                     +----+----+
 * |         |                     |         |
 * |   RT4   |                     |   RT5   |
 * |         |                     |         |
 * |         |                     |         |
 * +----+----+                     +----+----+
 *      |                               |
 *      |                               |
 *      |                               |
 *      |          +---------+          |
 *      |          |         |          |
 *      |          |   RT6   |          |
 *      +----------+         +----------+
 *                 |         |
 *                 +---------+
 *
 * Test topology 2:
 * ================
 *
 *                 +---------+
 *                 |         |
 *                 |   RT1   |
 *      +----------+         +----------+
 *      |          |         |          |
 *      |          +----+----+          |
 *      |               |               |
 *   15 |               |               | 30
 *      |               |               |
 * +----+----+          |          +----+----+
 * |         |          |          |         |
 * |   RT2   |          |          |   RT3   |
 * |         |          |          |         |
 * |         |          |          |         |
 * +----+----+          |          +----+----+
 *      |               |               |
 *   40 |               |               | 40
 *      |               |               |
 * +----+----+          |          +----+----+
 * |         |          |          |         |
 * |   RT4   |          |          |   RT5   |
 * |         +----------+----------+         |
 * |         |                     |         |
 * +----+----+                     +----+----+
 *      |                               |
 *      |                               |
 *      |                               |
 *      |          +---------+          |
 *      |          |         |          |
 *      |          |   RT6   |          |
 *      +----------+         +----------+
 *                 |         |
 *                 +---------+
 *
 * Test topology 3:
 * ================
 *
 *                 +---------+
 *                 |         |
 *                 |   RT1   |
 *      +----------+         +----------+
 *      |          |         |          |
 *      |          +---------+          |
 *      |                               |
 *      |                               |
 *      |                               |
 * +----+----+                     +----+----+
 * |         |                     |         |
 * |   RT2   |                     |   RT3   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +----+----+                     +----+----+
 *      |                               |
 *      |                               | 30
 *      |                               |
 * +----+----+                     +----+----+
 * |         |                     |         |
 * |   RT4   |                     |   RT5   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +----+----+                     +----+----+
 *      |                               |
 *      |                               |
 *      |                               |
 *      |          +---------+          |
 *      |          |         |          |
 *      |          |   RT6   |          |
 *      +----------+         +----------+
 *                 |         |
 *                 +---------+
 *
 * Test topology 4:
 * ================
 *
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |                     |   RT2   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT3   |                     |   RT4   |
 * |         |                     |         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |^                                 |
 *     ||200                              |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT5   |          50         |   RT6   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT7   |                     |   RT8   |
 * |         |                     |         |
 * |         |                     |         |
 * +---------+                     +---------+
 *
 * Test topology 5:
 * ================
 *
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |                     |   RT2   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT3   |                     |   RT4   |
 * |         |                     |         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT5   |                     |   RT6   |
 * |         |                     |         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT7   |                     |   RT8   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---------+                     +---------+
 *
 * Test topology 6:
 * ================
 *
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |                     |   RT2   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT3   |                     |   RT4   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---------+                     +------+--+
 *                                        |
 *                                        |
 *                                        |
 * +---------+                     +------+--+
 * |         |                     |         |
 * |   RT5   |                     |   RT6   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT7   |                     |   RT8   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---------+                     +---------+
 *
 * Test topology 7:
 * ================
 *
 * +---------+                     +---------+                     +---------+
 * |         |                     |         |                     |         |
 * |   RT1   |         40          |   RT2   |                     |   RT3   |
 * |         +---------------------+         +---------------------+         |
 * |         |                     |         |                     |         |
 * +---+-----+                     +----+----+                     +------+--+
 *     |                                |                                 |
 *     |                                |                                 |
 *     |                                |                                 |
 * +---+-----+                     +----+----+                     +------+--+
 * |         |                     |         |                     |         |
 * |   RT4   |                     |   RT5   |                     |   RT6   |
 * |         +---------------------+         +---------------------+         |
 * |         |                     |         |                     |         |
 * +---+-----+                     +----+----+                     +------+--+
 *     |                                |                                 |
 *     |                                |                                 | 30
 *     |                                |                                 |
 * +---+-----+                     +----+----+                     +------+--+
 * |         |                     |         |                     |         |
 * |   RT7   |                     |   RT8   |                     |   RT9   |
 * |         +---------------------+         +---------------------+         |
 * |         |                     |         |                     |         |
 * +---+-----+                     +----+----+                     +------+--+
 *     |                                |                                 |
 *     | 20                             |                                 |
 *     |                                |                                 |
 * +---+-----+                     +----+----+                     +------+--+
 * |         |                     |         |                     |         |
 * |   RT10  |                     |   RT11  |                     |   RT12  |
 * |         +---------------------+         +---------------------+         |
 * |         |                     |         |                     |         |
 * +---------+                     +---------+                     +---------+
 *
 * Test topology 8:
 * ================
 *
 * +---------+                     +---------+                     +---------+
 * |         |                     |         |                     |         |
 * |   RT1   |                     |   RT2   |                     |   RT3   |
 * |         +---------------------+         +---------------------+         |
 * |         |                     |         |                     |         |
 * +---+-----+                     +----+----+                     +------+--+
 *     |                                |                                 |
 *     |                                |                                 |
 *     |                                |                                 |
 * +---+-----+                     +----+----+                     +------+--+
 * |         |                     |         |                     |         |
 * |   RT4   |                     |   RT5   |                     |   RT6   |
 * |         |                     |         +---------------------+         |
 * |         |                     |         |                     |         |
 * +---+-----+                     +----+----+                     +---------+
 *     |                                |
 *     |                                |
 *     |                                |
 * +---+-----+                     +----+----+                     +---------+
 * |         |                     |         |                     |         |
 * |   RT7   |                     |   RT8   |                     |   RT9   |
 * |         |                     |         +---------------------+         |
 * |         |                     |         |                     |         |
 * +---+-----+                     +----+----+                     +------+--+
 *     |                                |                                 |
 *     |                                |                                 |
 *     |                                |                                 |
 * +---+-----+                     +----+----+                     +------+--+
 * |         |                     |         |                     |         |
 * |   RT10  |                     |   RT11  |                     |   RT12  |
 * |         +---------------------+         +---------------------+         |
 * |         |          30         |         |                     |         |
 * +---------+                     +---------+                     +---------+
 *
 * Test topology 9:
 * ================
 *
 *                       +---------+
 *                       |         |
 *                       |   RT1   |
 *            +----------+         +----------+
 *            |          |         |          |
 *            |          +---------+          |
 *            |                               |
 *            |                               |
 *            |                               |
 *       +----+----+                     +----+----+
 *       |         |                     |         |
 *       |   RT2   |                     |   RT3   |
 *       |         |                     |         |
 *       |         |                     |         |
 *       +----+----+                     +------+--+
 *            |                                 |
 *            |                                 |
 *            |                                 |100
 *            |          +---------+            |
 *            |          |         |            |
 *            +----------+   RT4   +------------+
 *      +----------------|         |----------------+
 *      |              +-+         +--+             |
 *      |              | +---------+  |             |
 *      |              |              |             |
 *      |              |30            |30           |30
 *      |              |              |             |
 * +----+----+    +----+----+    +----+----+   +----+----+
 * |         |    |         |    |         |   |         |
 * |   RT5   |    |   RT6   |    |   RT7   |   |   RT8   |
 * |         |    |         |    |         |   |         |
 * |         |    |         |    |         |   |         |
 * +----+----+    +----+----+    +----+----+   +----+----+
 *      |              |              |             |
 *      |              |              |             |
 *      |              |              |             |
 *      |              | +---------+  |             |
 *      |              +-+         +--+             |
 *      +----------------+   RT9   +----------------+
 *                       |         |
 *                       |         |
 *                       +---------+
 *
 * Test topology 10:
 * ================
 *
 *                 +---------+
 *                 |         |
 *                 |   RT1   |
 *      +----------+         +----------+
 *      |          |         |          |
 *      |          +----+----+          |
 *      |               |               |
 *      |               |20             |20
 *      |               |               |
 * +----+----+     +----+----+     +----+----+
 * |         |     |         |     |         |
 * |   RT2   |     |   RT3   |     |   RT4   |
 * |         |     |         |     |         |
 * |         |     |         |     |         |
 * +----+----+     +----+----+     +----+----+
 *      |               |               |
 *      |               |               |
 *      |               |               |
 * +----+----+     +----+----+     +----+----+
 * |         |     |         |     |         |
 * |   RT5   |     |   RT6   |     |   RT7   |
 * |         |     |         |     |         |
 * |         |     |         |     |         |
 * +----+----+     +----+----+     +----+----+
 *      |               |               |
 *      |               |50             |50
 *      |               |               |
 *      |          +----+----+          |
 *      |          |         |          |
 *      +----------+   RT8   +----------+
 *                 |         |
 *                 |         |
 *                 +---------+
 *
 * Test topology 11:
 * ================
 *
 *                 +---------+
 *                 |         |
 *                 |   RT1   |
 *                 |         |
 *                 |         |
 *                 +----+----+
 *                      |
 *                      |
 *                      |
 * +---------+          |          +---------+
 * |         |          |          |         |
 * |   RT2   |50        |          |   RT3   |
 * |         +----------+----------+         |
 * |         |                     |         |
 * +----+----+                     +----+----+
 *      |                               |
 *      |                               |
 *      |                               |
 * +----+----+                     +----+----+
 * |         |                     |         |
 * |   RT4   |                     |   RT5   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +----+----+                     +----+----+
 *      |                               |
 *      |                               |
 *      |                               |
 *      |          +---------+          |
 *      |          |         |          |
 *      |          |   RT6   |          |
 *      +----------+         +----------+
 *                 |         |
 *                 +---------+
 *
 * Test topology 12:
 * ================
 *
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |                     |   RT2   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT3   |                     |   RT4   |
 * |         |                     |         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |^                                 |
 *     |400                               |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT5   |                     |   RT6   |
 * |         |                     |         |
 * |         |                     |         |
 * +---+-----+                     +------+--+
 *     |^                                 |
 *     |200                               |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT7   |                     |   RT8   |
 * |         +---------------------+         |
 * |         |         100         |         |
 * +---+-----+                     +------+--+
 *     |                                  |
 *     |                                  |
 *     |                                  |
 * +---+-----+                     +------+--+
 * |         |                     |         |
 * |   RT9   |                     |   RT10  |
 * |         |                     |         |
 * |         |                     |         |
 * +---------+                     +---------+
 *
 * Test topology 13:
 * ================
 *
 * +---------+                     +---------+
 * |         |                     |         |
 * |   RT1   |                     |   RT2   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---+-----+                     +----+----+
 *     |                                |
 *     |                                |
 *     |                                |
 *     |                           +----+----+
 *     |                           |         |
 *     |                +----------+   RT4   |
 *     |                |          |         |
 * +---+-----+          |          |         |
 * |         |          |          +----+----+
 * |   RT3   +----------+               |
 * |         +----------+               |100
 * |         |          |               |
 * +---+-----+          |          +----+----+
 *     |                |          |         |
 *     |                |          |   RT5   |
 *     |                +----------+         |
 *     |                           |         |
 *     |                           +----+----+
 *     |                                |
 *     |                                |
 *     |                                |
 * +---+-----+                     +----+----+
 * |         |                     |         |
 * |   RT6   |                     |   RT7   |
 * |         +---------------------+         |
 * |         |                     |         |
 * +---------+                     +---------+

 * Test topology 14:
 * =================
 *
 * +---------+              +---------+
 * |         |              |         |
 * |   RT1   |              |   RT2   |
 * |         +--------------+         |
 * |         |              |         |
 * +----+----+              +----+----+
 *      |                        |
 *      |                        |
 *      |                        |
 *      |                   +----+----+
 *      |                   |         |
 *      |                   |   RT3   |
 *      +-------------------+         |
 *      |                   |         |
 *      |                   +----+----+
 *      |                        |
 *      |                        |50
 *      |                        |
 * +----+----+              +----+----+
 * |         |              |         |
 * |   RT4   |              |   RT5   |
 * |         +--------------+         |
 * |         |              |         |
 * +---------+              +---------+
 */

struct isis_topology test_topologies[] = {
	{
		.number = 1,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.1/32",
					"2001:db8::1/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.2/32",
					"2001:db8::2/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.3/32",
					"2001:db8::3/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.4/32",
					"2001:db8::4/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.5/32",
					"2001:db8::5/128",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.6/32",
					"2001:db8::6/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 2,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.1/32",
					"2001:db8::1/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.pseudonode_id = 1,
						.metric = 10,
					},
					{
						.hostname = "rt2",
						.metric = 15,
					},
					{
						.hostname = "rt3",
						.metric = 30,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.2/32",
					"2001:db8::2/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 15,
					},
					{
						.hostname = "rt4",
						.metric = 40,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.3/32",
					"2001:db8::3/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 30,
					},
					{
						.hostname = "rt5",
						.metric = 40,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.4/32",
					"2001:db8::4/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.pseudonode_id = 1,
						.metric = 10,
					},
					{
						.hostname = "rt2",
						.metric = 40,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.5/32",
					"2001:db8::5/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.pseudonode_id = 1,
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 40,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.6/32",
					"2001:db8::6/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.pseudonode_id = 1,
				.level = IS_LEVEL_1,
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 0,
					},
					{
						.hostname = "rt4",
						.metric = 0,
					},
					{
						.hostname = "rt5",
						.metric = 0,
					},
				},
			},
		},
	},
	{
		.number = 3,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 30,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 30,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 4,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 200,
					},
					{
						.hostname = "rt6",
						.metric = 50,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 50,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.7/32",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.8/32",
				},
				.adjacencies = {
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 5,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.7/32",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.8/32",
				},
				.adjacencies = {
					{
						.hostname = "rt6",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 6,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt6",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.7/32",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.8/32",
				},
				.adjacencies = {
					{
						.hostname = "rt6",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 7,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 40,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 40,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt9",
						.metric = 30,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.7/32",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
					{
						.hostname = "rt10",
						.metric = 20,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.8/32",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
					{
						.hostname = "rt9",
						.metric = 10,
					},
					{
						.hostname = "rt11",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt9",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x09},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.9",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.9/32",
				},
				.adjacencies = {
					{
						.hostname = "rt6",
						.metric = 30,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
					{
						.hostname = "rt12",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt10",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.10",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.10/32",
				},
				.adjacencies = {
					{
						.hostname = "rt7",
						.metric = 20,
					},
					{
						.hostname = "rt11",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt11",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0b},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.11",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.11/32",
				},
				.adjacencies = {
					{
						.hostname = "rt8",
						.metric = 10,
					},
					{
						.hostname = "rt10",
						.metric = 10,
					},
					{
						.hostname = "rt12",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt12",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0c},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.12",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.12/32",
				},
				.adjacencies = {
					{
						.hostname = "rt9",
						.metric = 10,
					},
					{
						.hostname = "rt11",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 8,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.7/32",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt10",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.8/32",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt9",
						.metric = 10,
					},
					{
						.hostname = "rt11",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt9",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x09},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.9",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.9/32",
				},
				.adjacencies = {
					{
						.hostname = "rt8",
						.metric = 10,
					},
					{
						.hostname = "rt12",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt10",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.10",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.10/32",
				},
				.adjacencies = {
					{
						.hostname = "rt7",
						.metric = 10,
					},
					{
						.hostname = "rt11",
						.metric = 30,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt11",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0b},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.11",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.11/32",
				},
				.adjacencies = {
					{
						.hostname = "rt8",
						.metric = 10,
					},
					{
						.hostname = "rt10",
						.metric = 30,
					},
					{
						.hostname = "rt12",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt12",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0c},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.12",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.12/32",
				},
				.adjacencies = {
					{
						.hostname = "rt9",
						.metric = 10,
					},
					{
						.hostname = "rt11",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 9,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.1/32",
					"2001:db8::1/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.2/32",
					"2001:db8::2/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.3/32",
					"2001:db8::3/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 100,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.4/32",
					"2001:db8::4/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 100,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 30,
					},
					{
						.hostname = "rt7",
						.metric = 30,
					},
					{
						.hostname = "rt8",
						.metric = 30,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.5/32",
					"2001:db8::5/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt9",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.6/32",
					"2001:db8::6/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 30,
					},
					{
						.hostname = "rt9",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.7/32",
					"2001:db8::7/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 30,
					},
					{
						.hostname = "rt9",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.8/32",
					"2001:db8::8/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 30,
					},
					{
						.hostname = "rt9",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt9",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x09},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.9",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.9/32",
					"2001:db8::9/128",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 10,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.1/32",
					"2001:db8::1/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 20,
					},
					{
						.hostname = "rt4",
						.metric = 20,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.2/32",
					"2001:db8::2/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.srgb = {
					.lower_bound = 20000,
					.range_size = 8000,
				},
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.3/32",
					"2001:db8::3/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 20,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.4/32",
					"2001:db8::4/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 20,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.5/32",
					"2001:db8::5/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.6/32",
					"2001:db8::6/128",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 50,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.7/32",
					"2001:db8::7/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 50,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.8/32",
					"2001:db8::8/128",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 50,
					},
					{
						.hostname = "rt7",
						.metric = 50,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 11,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.1/32",
					"2001:db8::1/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.pseudonode_id = 1,
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.2/32",
					"2001:db8::2/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.pseudonode_id = 1,
						.metric = 50,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.3/32",
					"2001:db8::3/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.pseudonode_id = 1,
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.4/32",
					"2001:db8::4/128",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.5/32",
					"2001:db8::5/128",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.6/32",
					"2001:db8::6/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.pseudonode_id = 1,
				.level = IS_LEVEL_1,
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 0,
					},
					{
						.hostname = "rt2",
						.metric = 0,
					},
					{
						.hostname = "rt3",
						.metric = 0,
					},
				},
			},
		},
	},
	{
		.number = 12,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 400,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.7/32",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 200,
					},
					{
						.hostname = "rt8",
						.metric = 100,
					},
					{
						.hostname = "rt9",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt8",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x08},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.8",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.8/32",
				},
				.adjacencies = {
					{
						.hostname = "rt6",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 100,
					},
					{
						.hostname = "rt10",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt9",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x09},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.9",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.9/32",
				},
				.adjacencies = {
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt10",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x0a},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.10",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.10/32",
				},
				.adjacencies = {
					{
						.hostname = "rt8",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 13,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.1/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.2/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.3/32",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.4/32",
				},
				.adjacencies = {
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 100,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.5/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt4",
						.metric = 100,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt6",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x06},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.6",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.6/32",
				},
				.adjacencies = {
					{
						.hostname = "rt3",
						.metric = 10,
					},
					{
						.hostname = "rt7",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
			{
				.hostname = "rt7",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x07},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.7",
				.protocols = {
					.ipv4 = true,
				},
				.networks = {
					"10.0.255.7/32",
				},
				.adjacencies = {
					{
						.hostname = "rt5",
						.metric = 10,
					},
					{
						.hostname = "rt6",
						.metric = 10,
					},
				},
				.flags = F_ISIS_TEST_NODE_SR,
			},
		},
	},
	{
		.number = 14,
		.nodes = {
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.1",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.1/32",
					"2001:db8::1/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.pseudonode_id = 1,
						.metric = 10,
					},
					{
						.hostname = "rt2",
						.metric = 10,
					},
				},
			},
			{
				.hostname = "rt2",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.2",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.2/32",
					"2001:db8::2/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 20,
					},
					{
						.hostname = "rt3",
						.metric = 10,
					},
				},
			},
			{
				.hostname = "rt3",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x03},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.3",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.3/32",
					"2001:db8::3/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.pseudonode_id = 1,
						.metric = 10,
					},
					{
						.hostname = "rt2",
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 50,
					},
				},
			},
			{
				.hostname = "rt4",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x04},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.4",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.4/32",
					"2001:db8::4/128",
				},
				.adjacencies = {
					{
						.hostname = "rt1",
						.pseudonode_id = 1,
						.metric = 10,
					},
					{
						.hostname = "rt5",
						.metric = 10,
					},
				},
			},
			{
				.hostname = "rt5",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x05},
				.level = IS_LEVEL_1,
				.router_id = "10.0.255.5",
				.protocols = {
					.ipv4 = true,
					.ipv6 = true,
				},
				.networks = {
					"10.0.255.5/32",
					"2001:db8::5/128",
				},
				.adjacencies = {
					{
						.hostname = "rt4",
						.metric = 10,
					},
					{
						.hostname = "rt3",
						.metric = 50,
					},
				},
			},
			{
				.hostname = "rt1",
				.sysid = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
				.pseudonode_id = 1,
				.level = IS_LEVEL_1,
				.adjacencies = {
					{
						.hostname = "rt1",
						.metric = 0,
					},
					{
						.hostname = "rt3",
						.metric = 0,
					},
					{
						.hostname = "rt4",
						.metric = 0,
					},
				},
			},
		},
	},
	{
		/* sentinel */
	},
};
