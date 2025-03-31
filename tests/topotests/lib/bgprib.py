#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright 2018, LabN Consulting, L.L.C.

#
# want_rd_routes = [
#     {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1', 'bp': True},
#     {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1', 'bp': False},
#
#     {'rd':'10:3', 'p':'5.1.0.0/24', 'n':'3.3.3.3'},
# ]
#
# ribRequireVpnRoutes('r2','Customer routes',want_rd_routes)
#
# want_unicast_routes = [
#     {'p':'5.1.0.0/24', 'n':'1.1.1.1'},
# ]
#
# ribRequireUnicastRoutes('r1','ipv4','r1-cust1','Customer routes in vrf',want_unicast_routes)
# ribRequireUnicastRoutes('r1','ipv4','','Customer routes in default',want_unicast_routes)
#

from lib.lutil import luCommand, luResult, LUtil
import json
import re


# gpz: get rib in json form and compare against desired routes
class BgpRib:
    def log(self, str):
        LUtil.log("BgpRib: " + str)

    def routes_include_wanted(self, pfxtbl, want, debug):
        # helper function to RequireVpnRoutes
        for pfx in pfxtbl.keys():
            if debug:
                self.log("trying pfx %s" % pfx)
            if pfx != want["p"]:
                if debug:
                    self.log("want pfx=" + want["p"] + ", not " + pfx)
                continue
            if debug:
                self.log("have pfx=%s" % pfx)
            for r in pfxtbl[pfx]:
                bp = r.get("bestpath", False)
                if debug:
                    self.log("trying route %s bp=%s" % (r, bp))
                nexthops = r["nexthops"]
                for nh in nexthops:
                    if debug:
                        self.log("trying nh %s" % nh["ip"])
                    if nh["ip"] == want["n"]:
                        if debug:
                            self.log("found %s" % want["n"])
                        if bp == want.get("bp", bp):
                            return 1
                        elif debug:
                            self.log("bestpath mismatch %s != %s" % (bp, want["bp"]))
                    else:
                        if debug:
                            self.log("want nh=" + want["n"] + ", not " + nh["ip"])
            if debug:
                self.log("missing route: pfx=" + want["p"] + ", nh=" + want["n"])
            return 0

    def RequireVpnRoutesOne(self, target, title, wantroutes, debug=0):
        import json

        # non json form for humans
        luCommand(
            target,
            'vtysh -c "show bgp ipv4 vpn"',
            ".",
            "None",
            "Get VPN RIB (non-json)",
        )
        ret = luCommand(
            target,
            'vtysh -c "show bgp ipv4 vpn json"',
            ".*",
            "None",
            "Get VPN RIB (json)",
        )
        if re.search(r"^\s*$", ret):
            # degenerate case: empty json means no routes
            if len(wantroutes) > 0:
                return False
            return True
        rib = json.loads(ret)
        try:
            rds = rib["routes"]["routeDistinguishers"]
        except KeyError as err:
            # KeyError: 'routes' probably means missing/bad VRF
            # This error also happens if we are too quick and the routing
            # table has not been fully populated yet.
            if debug:
                self.log("KeyError, no routes")
            return False
        for want in wantroutes:
            found = 0
            if debug:
                self.log("want rd %s" % want["rd"])
            for rd in rds.keys():
                if rd != want["rd"]:
                    continue
                if debug:
                    self.log("found rd %s" % rd)
                table = rds[rd]
                if self.routes_include_wanted(table, want, debug):
                    found = 1
                    break
            if not found:
                return False
        return True

    def RequireVpnRoutes(
        self, target, title, wantroutes, debug=0, wait=10, wait_time=0.5
    ):
        import time
        import math

        logstr = "RequireVpnRoutes " + str(wantroutes)
        found = False
        n = 0
        startt = time.time()

        # Calculate the amount of `sleep`s we are going to peform.
        wait_count = int(math.ceil(wait / wait_time)) + 1

        while wait_count > 0:
            n += 1
            found = self.RequireVpnRoutesOne(target, title, wantroutes, debug)
            if found is not False:
                break

            wait_count -= 1
            if wait_count > 0:
                time.sleep(wait_time)

        delta = time.time() - startt
        self.log("Done after %d loops, time=%s, Found=%s" % (n, delta, found))
        luResult(target, found, title, logstr)
        return found

    def RequireUnicastRoutesOne(self, target, afi, vrf, title, wantroutes, debug=0):
        logstr = "RequireUnicastRoutes %s" % str(wantroutes)
        vrfstr = ""
        if vrf != "":
            vrfstr = "vrf %s" % (vrf)

        if (afi != "ipv4") and (afi != "ipv6"):
            self.log("ERROR invalid afi")

        cmdstr = "show bgp %s %s unicast" % (vrfstr, afi)
        # non json form for humans
        cmd = 'vtysh -c "%s"' % cmdstr
        luCommand(target, cmd, ".", "None", "Get %s %s RIB (non-json)" % (vrfstr, afi))
        cmd = 'vtysh -c "%s json"' % cmdstr
        ret = luCommand(
            target, cmd, ".*", "None", "Get %s %s RIB (json)" % (vrfstr, afi)
        )
        if re.search(r"^\s*$", ret):
            # degenerate case: empty json means no routes
            if len(wantroutes) > 0:
                return False, ""
            return True, ""
        rib = json.loads(ret)
        try:
            table = rib["routes"]
            # KeyError: 'routes' probably means missing/bad VRF
        except KeyError as err:
            if vrf != "":
                errstr = "-script ERROR: check if wrong vrf (%s)" % (vrf)
            else:
                errstr = "-script ERROR: check if vrf missing"
            self.log(errstr)
            return False, errstr
        # if debug:
        #    self.log("table=%s" % table)
        for want in wantroutes:
            if debug:
                self.log("want=%s" % want)
            if not self.routes_include_wanted(table, want, debug):
                return False, ""
        return True, ""

    def RequireUnicastRoutes(
        self, target, afi, vrf, title, wantroutes, debug=0, wait=10, wait_time=0.5
    ):
        import time
        import math

        logstr = "RequireUnicastRoutes %s" % str(wantroutes)
        found = False
        n = 0
        startt = time.time()
        errstr = ""

        # Calculate the amount of `sleep`s we are going to peform.
        wait_count = int(math.ceil(wait / wait_time)) + 1

        while wait_count > 0:
            n += 1
            found, errstr = self.RequireUnicastRoutesOne(
                target, afi, vrf, title, wantroutes, debug
            )
            if found is not False:
                break

            wait_count -= 1
            if wait_count > 0:
                time.sleep(wait_time)

        delta = time.time() - startt
        self.log("Done after %d loops, time=%s, Found=%s" % (n, delta, found))
        luResult(target, found, title + errstr, logstr)
        return found


BgpRib = BgpRib()


def bgpribRequireVpnRoutes(target, title, wantroutes, debug=0, wait=10, wait_time=0.5):
    BgpRib.RequireVpnRoutes(target, title, wantroutes, debug, wait, wait_time)


def bgpribRequireUnicastRoutes(
    target, afi, vrf, title, wantroutes, debug=0, wait=10, wait_time=0.5
):
    BgpRib.RequireUnicastRoutes(
        target, afi, vrf, title, wantroutes, debug, wait, wait_time
    )
