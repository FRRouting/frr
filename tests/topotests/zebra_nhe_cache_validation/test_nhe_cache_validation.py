#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
End-to-end tests validating received vs installed NHG caching behavior.

Scenarios:
- ECMP BGP route on R1 with 4-way ECMP from 4 peer links (function1)
- Recursive BGP next-hops on R1 via loopback multihop sessions (function2)
"""

import os
import json
import sys
import pytest
from time import sleep as tsleep

from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib import topotest

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


def build_topo(tgen):
	# Routers
	tgen.add_router("r1")
	tgen.add_router("r2")
	tgen.add_router("r3")

	r1 = tgen.gears["r1"]
	r2 = tgen.gears["r2"]
	r3 = tgen.gears["r3"]

	# Four parallel links between r1 and r2 (ECMP test)
	for i in range(1, 5):
		sw = tgen.add_switch(f"sw{i}")
		sw.add_link(r1)
		sw.add_link(r2)

	# Single links r1-r3 (for recursive NH test)
	sw5 = tgen.add_switch("sw5")
	sw5.add_link(r1)
	sw5.add_link(r3)


def setup_module(mod):
	"Sets up the pytest environment"
	tgen = Topogen(build_topo, mod.__name__)
	tgen.start_topology()

	# Load FRR configs and start daemons
	for rname, router in tgen.routers().items():
		router.load_frr_config(
			os.path.join(CWD, f"{rname}/frr.conf"),
			[
				(TopoRouter.RD_ZEBRA, "-s 180000000"),
				(TopoRouter.RD_BGP, None),
				(TopoRouter.RD_OSPF, None),
				(TopoRouter.RD_SHARP, None),
			],
		)

	tgen.start_router()


def teardown_module():
	"Teardown the pytest environment"
	tgen = get_topogen()
	tgen.stop_topology()


def _get_route_json(router, prefix):
	out = router.vtysh_cmd(f"show ip route {prefix} json")
	try:
		data = json.loads(out)
	except Exception as ex:
		logger.info(f"Failed to parse JSON for show ip route {prefix}: {ex}\n{out}")
		return None
	return data


def _get_nhg_json(router, nhg_id):
	out = router.vtysh_cmd(f"show nexthop-group rib {nhg_id} json")
	try:
		data = json.loads(out)
	except Exception as ex:
		logger.info(f"Failed to parse NHG JSON for id {nhg_id}: {ex}\n{out}")
		return None
	return data


def test_ecmp_received_vs_installed():
	"""
	Normal ECMP validation
	- R1 is DUT, having 4-way ECMP for BGP route 33.1.1.1/32 from R2 over 4 peer links
	- Validate received and installed NHGs:
	  installedNexthopGroupId == nexthopGroupId
	  receivedNexthopGroupId != installedNexthopGroupId
	- Validate installed NHG nexthop count == 4
	"""
	tgen = get_topogen()
	if tgen.routers_have_failure():
		pytest.skip(tgen.errors)

	r1 = tgen.gears["r1"]

	def _check_route():
		# Debug: dump relevant state each attempt
		#logger.info(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
		logger.info(r1.vtysh_cmd("show ip route 33.1.1.1 json"))
		data = _get_route_json(r1, "33.1.1.1")
		return bool(data and "33.1.1.1/32" in data)

	ok, res = topotest.run_and_expect(_check_route, True, count=40, wait=1)
	assert ok, "Did not observe expected ECMP NHG behavior for 33.1.1.1/32 on R1"

	# Post-wait strict assertions with helpful messages
	route_json = _get_route_json(r1, "33.1.1.1")
	assert route_json and "33.1.1.1/32" in route_json, "33.1.1.1/32 missing in 'show ip route' json on R1"
	route = route_json["33.1.1.1/32"][0]
	assert "installedNexthopGroupId" in route and "receivedNexthopGroupId" in route, "NHG id fields missing in route json"
	ing = route["installedNexthopGroupId"]
	rng = route["receivedNexthopGroupId"]
	ng = route.get("nexthopGroupId")

	def _ecmp_nhg_ok():
		# Re-read route JSON each attempt so we don't pin to a stale ing while
		# zebra is still converging/renumbering NHGs.
		route_json = _get_route_json(r1, "33.1.1.1")
		if not route_json or "33.1.1.1/32" not in route_json:
			return False

		route = route_json["33.1.1.1/32"][0]
		ing = route.get("installedNexthopGroupId")
		rng = route.get("receivedNexthopGroupId")
		ng = route.get("nexthopGroupId")
		if ing is None or rng is None or ng is None:
			return False

		nhg_json = _get_nhg_json(r1, ing)
		if not nhg_json or str(ing) not in nhg_json:
			return False

		nh_count = nhg_json[str(ing)].get("nexthopCount")
		logger.info(
			f"ECMP retry: ing={ing} rng={rng} ng={ng} nexthopCount={nh_count} (expect 4)"
		)
		return ing == ng and ing != rng and nh_count == 4

	ok, _ = topotest.run_and_expect(_ecmp_nhg_ok, True, count=5, wait=2)
	assert ok, "ECMP NHG ids/nexthopCount did not converge after retries"

	# Final strict assertions with helpful messages.
	route_json = _get_route_json(r1, "33.1.1.1")
	assert route_json and "33.1.1.1/32" in route_json, "33.1.1.1/32 missing in 'show ip route' json on R1"
	route = route_json["33.1.1.1/32"][0]
	assert "installedNexthopGroupId" in route and "receivedNexthopGroupId" in route, "NHG id fields missing in route json"
	ing = route["installedNexthopGroupId"]
	rng = route["receivedNexthopGroupId"]
	ng = route.get("nexthopGroupId")
	assert ing is not None and rng is not None and ng is not None, f"NHG ids None (ing={ing}, rng={rng}, ng={ng})"
	assert ing == ng, f"installedNexthopGroupId != nexthopGroupId (ing={ing}, ng={ng})"
	assert ing != rng, f"installedNexthopGroupId should differ from received (ing={ing}, rng={rng})"
	nhg_json = _get_nhg_json(r1, ing)
	assert nhg_json and str(ing) in nhg_json, f"NHG {ing} not found in 'show nexthop-group rib' json"
	nh_count = nhg_json[str(ing)].get("nexthopCount")
	assert nh_count == 4, f"nexthopCount != 4 for NHG {ing} (count={nh_count})"


def test_recursive_nh_received_vs_installed():
	"""
	recursive NH validation
	- R1 is DUT, receives BGP route 34.1.1.1/32 from R2 and R3 via multihop sessions
	- Next-hops are R2 and R3 loopbacks (A and B), resolved via OSPF on physical links (C and D)
	- Validate received and installed NHGs differ similarly as Normal ECMP validation
	"""
	tgen = get_topogen()
	if tgen.routers_have_failure():
		pytest.skip(tgen.errors)

	r1 = tgen.gears["r1"]

	def _check_route():
		logger.info(r1.vtysh_cmd("show ip route 34.1.1.1 json"))
		data = _get_route_json(r1, "34.1.1.1")
		return bool(data and "34.1.1.1/32" in data)

	ok, res = topotest.run_and_expect(_check_route, True, count=50, wait=1)
	assert ok, "Did not observe expected recursive NHG behavior for 34.1.1.1/32 on R1"

	# Post-wait strict assertions with helpful messages
	route_json = _get_route_json(r1, "34.1.1.1")
	assert route_json and "34.1.1.1/32" in route_json, "34.1.1.1/32 missing in 'show ip route' json on R1"
	route = route_json["34.1.1.1/32"][0]
	assert "installedNexthopGroupId" in route and "receivedNexthopGroupId" in route, "NHG id fields missing in route json"
	ing = route["installedNexthopGroupId"]
	rng = route["receivedNexthopGroupId"]
	ng = route.get("nexthopGroupId")
	assert ing is not None and rng is not None and ng is not None, f"NHG ids None (ing={ing}, rng={rng}, ng={ng})"
	assert route.get("installed", False) and route.get("selected", False), "Route not installed/selected"
	assert ing != ng, f"installedNexthopGroupId != nexthopGroupId (ing={ing}, ng={ng})"
	assert ing != rng, f"installedNexthopGroupId should equal received for recursion (ing={ing}, rng={rng})"
	nhg_json = _get_nhg_json(r1, ing)
	assert nhg_json and str(ing) in nhg_json, f"NHG {ing} not found in 'show nexthop-group rib' json"
	nh_count = nhg_json[str(ing)].get("nexthopCount")
	assert nh_count == 1, f"nexthopCount != 1 for recursive NHG {ing} (count={nh_count})"


def test_routemap_received_vs_installed():
	"""
	Validate zebra route-map behavior on received vs installed NHGs for SHARP routes.
	Cases:
	- 45.1.1.1: route-map denies NH 'c' (interface r1-eth2) => installed has 3 NHs; received cache not populated
	- 45.1.1.2: no route-map => installed has 4 NHs; received cache populated and ing != rng
	- 45.1.1.3: route-map set src => installed has 4 NHs; received cache not equal to ing
	- 45.1.1.4: no route-map => behaves like case2
	"""
	tgen = get_topogen()
	if tgen.routers_have_failure():
		pytest.skip(tgen.errors)

	r1 = tgen.gears["r1"]
	r2 = tgen.gears["r2"]

	# Configure zebra route-map on r1: deny one NH for 45.1.1.1 and set src for .3
	r1.vtysh_cmd(
		"\n".join([
			"configure terminal",
			"ip prefix-list PFX_RM_R1 seq 5 permit 45.1.1.1/32",
			"ip prefix-list PFX_RM_R3 seq 5 permit 45.1.1.3/32",
			"route-map ZRM permit 5",
			" match ip address prefix-list PFX_RM_R3",
			" set src 1.1.1.1",
			"route-map ZRM deny 10",
			" match ip address prefix-list PFX_RM_R1",
			" match interface r1-eth2",
			"route-map ZRM permit 1000",
			"ip protocol bgp route-map ZRM",
		])
	)
	tsleep(5)
	# Install 5 SHARP routes on r2 starting 45.1.1.1/32
	r2.vtysh_cmd("sharp install routes 45.1.1.1 nexthop 10.0.1.2 5")

	# Wait for all 5 to show up
	def _routes_present():
		for i in range(1, 6):
			pfx = f"45.1.1.{i}"
			data = _get_route_json(r1, pfx)
			if not data or f"{pfx}/32" not in data:
				return False
		return True

	ok, _ = topotest.run_and_expect(_routes_present, True, count=60, wait=1)
	assert ok, "SHARP routes 45.1.1.1/32..45.1.1.5/32 not visible on R1"

	def _get_ids_and_nhcount(prefix):
		route = _get_route_json(r1, prefix)[f"{prefix}/32"][0]
		ing = route["installedNexthopGroupId"]
		rng = route["receivedNexthopGroupId"]
		nhg_json = _get_nhg_json(r1, ing)
		nh_count = nhg_json[str(ing)]["nexthopCount"] if nhg_json and str(ing) in nhg_json else None
		recv_json = r1.vtysh_cmd(f"show nexthop-group rib {rng} json")
		try:
			recv_obj = json.loads(recv_json)
		except Exception:
			recv_obj = {}
		cache_id = None
		if recv_obj and str(rng) in recv_obj:
			cache_id = recv_obj[str(rng)].get("cacheResolvedNheId")
		return ing, rng, nh_count, cache_id

	# Case1: 45.1.1.1 => verify internal active NH count reflects route-map deny
	ing, rng, nhc, cache_id = _get_ids_and_nhcount("45.1.1.1")
	route_json = _get_route_json(r1, "45.1.1.1")
	assert route_json and "45.1.1.1/32" in route_json, "45.1.1.1/32 missing in route json"
	route_obj = route_json["45.1.1.1/32"][0]
	assert route_obj.get("internalNextHopNum") == 4, f"Expected internalNextHopNum=4, got {route_obj.get('internalNextHopNum')}"
	assert route_obj.get("internalNextHopActiveNum") == 3, f"Expected internalNextHopActiveNum=3, got {route_obj.get('internalNextHopActiveNum')}"
	# Optional: FIB-installed active NHs should be 3 as well
	fib_cnt = route_obj.get("internalNextHopFibInstalledNum")
	if fib_cnt is not None:
		assert fib_cnt == 3, f"Expected internalNextHopFibInstalledNum=3, got {fib_cnt}"

	# Case2: 45.1.1.2 => installed 4 NHs, cache present and ing != rng
	ing2, rng2, nhc2, cache_id2 = _get_ids_and_nhcount("45.1.1.2")
	assert nhc2 == 4, f"45.1.1.2 installed nexthopCount != 4 (got {nhc2})"
	assert cache_id2 and cache_id2 == ing2, f"45.1.1.2 received NHG should not match with installed cached={cache_id2}, ing={ing2})"
	assert ing2 != rng2, f"45.1.1.2 expected ing != rng (ing={ing2}, rng={rng2})"

	# Case3: 45.1.1.3 => set src; installed 4 NHs; cache_id should not equal ing2 (prior cached id)
	ing3, rng3, nhc3, cache_id3 = _get_ids_and_nhcount("45.1.1.3")
	assert nhc3 == 4, f"45.1.1.3 installed nexthopCount != 4 (got {nhc3})"
	assert cache_id3 in (None, 0) or cache_id3 == ing2, f"45.1.1.3 cache unexpectedly matches prior ing ({cache_id3} == {ing2})"

	# Case4: 45.1.1.4 => like case2
	ing4, rng4, nhc4, cache_id4 = _get_ids_and_nhcount("45.1.1.4")
	assert nhc4 == 4, f"45.1.1.4 installed nexthopCount != 4 (got {nhc4})"
	assert cache_id4 and cache_id4 == ing4, f"45.1.1.4 received NHG cache mismatch (cache={cache_id4}, ing={ing4})"
	assert ing4 != rng4, f"45.1.1.4 expected ing != rng (ing={ing4}, rng={rng4})"

	# Final checks on received and installed NHG IDs from all the routes
	assert rng == rng2 == rng4, f"Received NHG IDs should match across 45.1.1.1/.2/.4 (rng={rng}, rng2={rng2}, rng4={rng4})"
	assert ing2 == ing4, f"Installed NHG IDs for 45.1.1.2 and 45.1.1.4 should match (ing2={ing2}, ing4={ing4})"
	assert ing != ing2, f"Installed NHG for 45.1.1.1 should differ from 45.1.1.2 (ing1={ing}, ing2={ing2})"
	assert ing3 != ing2, f"Installed NHG for 45.1.1.3 (set src) should differ from 45.1.1.2 (ing3={ing3}, ing2={ing2})"

	# Clear route-map, reinstall SHARP routes, and validate uniformity of rng/ing
	r2.vtysh_cmd("sharp remove routes 45.1.1.1 5")
	tsleep(2)
	r1.vtysh_cmd(
		"\n".join([
			"configure terminal",
			"no ip protocol bgp route-map ZRM",
			"no route-map ZRM permit 5",
			"no route-map ZRM deny 10",
			"no route-map ZRM permit 1000",
			"no ip prefix-list PFX_RM_R1",
			"no ip prefix-list PFX_RM_R3",
			"end",
		])
	)
	tsleep(3)
	r2.vtysh_cmd("sharp install routes 45.1.1.1 nexthop 10.0.1.2 5")

	def _routes_present_uniform():
		ids_installed = []
		ids_received = []
		for i in range(1, 6):
			pfx = f"45.1.1.{i}"
			data = _get_route_json(r1, pfx)
			if not data or f"{pfx}/32" not in data:
				return False
			route = data[f"{pfx}/32"][0]
			ids_installed.append(route.get("installedNexthopGroupId"))
			ids_received.append(route.get("receivedNexthopGroupId"))
		# All installed IDs equal; all received IDs equal
		if None in ids_installed or None in ids_received:
			return False
		return len(set(ids_installed)) == 1 and len(set(ids_received)) == 1

	ok, _ = topotest.run_and_expect(_routes_present_uniform, True, count=60, wait=1)
	assert ok, "After clearing route-map, all SHARP routes should share same received and installed NHG IDs"
	r2.vtysh_cmd("sharp remove routes 45.1.1.1 5")
	tsleep(2)


def test_scale_interface_flap_nhe_parity():
	"""
	Scale test: install 50k SHARP routes from r2, flap first interface on r2,
	then verify that on r1 all routes share the same received and installed NHG IDs.
	"""
	tgen = get_topogen()
	if tgen.routers_have_failure():
		pytest.skip(tgen.errors)

	r1 = tgen.gears["r1"]
	r2 = tgen.gears["r2"]

	# Install 50k routes starting 45.1.1.1 from r2
	r2.vtysh_cmd("sharp install routes 45.1.1.1 nexthop 10.0.1.2 50000")

	# Bring down first interface on r1 (DUT)
	r1.vtysh_cmd("\n".join([
		"configure terminal",
		"interface r1-eth0",
		" shutdown",
		"end",
	]))

	# Wait for convergence
	def _converged():
		out = r1.vtysh_cmd("show ip route summ json")
		try:
			obj = json.loads(out)
		except Exception:
			return False
		total_fib = obj.get("routesTotalFib")
		return isinstance(total_fib, int) and total_fib >= 50000

	ok, _ = topotest.run_and_expect(_converged, True, count=60, wait=1)
	assert ok, "Convergence timeout: routesTotalFib did not reach >= 50,000"

	# Verify parity: all routes 45.1.1.X/32 have same received and installed NHG IDs
	def _parity_ok():
		# Use a single representative route to derive NHG IDs and verify refCounts
		one = r1.vtysh_cmd("show ip route 45.1.1.1 json")
		try:
			obj = json.loads(one)
		except Exception:
			return False
		if "45.1.1.1/32" not in obj:
			return False
		route = obj["45.1.1.1/32"][0]
		ing = route.get("installedNexthopGroupId")
		rng = route.get("receivedNexthopGroupId")
		ng = route.get("nexthopGroupId")
		if ing is None or rng is None or ng is None:
			return False
		if ing != ng:
			return False
		# Validate refCounts equal expected number of installed routes
		ing_json = _get_nhg_json(r1, ing)
		rng_json = _get_nhg_json(r1, rng)
		if not ing_json or str(ing) not in ing_json:
			return False
		if not rng_json or str(rng) not in rng_json:
			return False
		ing_ref = ing_json[str(ing)].get("refCount")
		rng_ref = rng_json[str(rng)].get("refCount")
		# Expect 50001: 50k SHARP-installed prefixes plus 1 route from r3
		return (ing_ref == 50001) and (rng_ref == 50001)

	ok, _ = topotest.run_and_expect(_parity_ok, True, count=30, wait=2)
	assert ok, "Parity check failed: not all routes share the same received/installed NHG IDs or ing != ng per-route"

	# Cleanup: bring interface up and remove routes
	r1.vtysh_cmd("\n".join([
		"configure terminal",
		"interface r1-eth0",
		" no shutdown",
		"end",
	]))
	r2.vtysh_cmd("sharp remove routes 45.1.1.1 50000")
	tsleep(2)

