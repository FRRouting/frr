#!/usr/bin/env python

#  
# want_rd_routes = [
#     {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1'},
#     {'rd':'10:1', 'p':'5.1.0.0/24', 'n':'1.1.1.1'},
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

from lutil import luCommand,luResult
import json
import re

# gpz: get rib in json form and compare against desired routes
class BgpRib:
    def routes_include_wanted(self,pfxtbl,want,debug):
	# helper function to RequireVpnRoutes
	for pfx in pfxtbl.iterkeys():
	    if debug:
		print 'trying pfx ' + pfx
	    if pfx != want['p']:
		if debug:
		    print 'want pfx=' + want['p'] + ', not ' + pfx
		continue
	    if debug:
		print 'have pfx=' + pfx
	    for r in pfxtbl[pfx]:
		if debug:
		    print 'trying route'
		nexthops = r['nexthops']
		for nh in nexthops:
		    if debug:
			print 'trying nh ' + nh['ip']
		    if nh['ip'] == want['n']:
			if debug:
			    print 'found ' + want['n']
			return 1
		    else:
			if debug:
			    print 'want nh=' + want['n'] + ', not ' + nh['ip']
	    if debug:
		print 'missing route: pfx=' + want['p'] + ', nh=' + want['n']
	    return 0

    def RequireVpnRoutes(self, target, title, wantroutes, debug=0):
	import json
	ret = luCommand(target,'vtysh -c "show bgp ipv4 vpn json"','.*','None','Get VPN RIB')
        if re.search(r'^\s*$', ret):
            # degenerate case: empty json means no routes
            if len(wantroutes) > 0:
                luResult(target, False, title)
                return
            luResult(target, True, title)
	rib = json.loads(ret)
	rds = rib['routes']['routeDistinguishers']
	for want in wantroutes:
	    found = 0
	    if debug:
		print "want rd " + want['rd']
	    for rd in rds.iterkeys():
		if rd != want['rd']:
		    continue
		if debug:
		    print "found rd " + rd
		table = rds[rd]
		if self.routes_include_wanted(table,want,debug):
		    found = 1
		    break
	    if not found:
		luResult(target, False, title)
		return
	luResult(target, True, title)

    def RequireUnicastRoutes(self,target,afi,vrf,title,wantroutes,debug=0):

	vrfstr = ''
	if vrf != '':
	    vrfstr = 'vrf %s' % (vrf)

	if (afi != 'ipv4') and (afi != 'ipv6'):
	    print "ERROR invalid afi";

	str = 'show bgp %s %s unicast json' % (vrfstr, afi)
	cmd = 'vtysh -c "%s"' % str
	ret = luCommand(target,cmd,'.*','None','Get %s %s RIB' % (vrfstr, afi))
        if re.search(r'^\s*$', ret):
            # degenerate case: empty json means no routes
            if len(wantroutes) > 0:
                luResult(target, False, title)
                return
            luResult(target, True, title)
	rib = json.loads(ret)
	table = rib['routes']
	for want in wantroutes:
	    if not self.routes_include_wanted(table,want,debug):
		luResult(target, False, title)
		return
	luResult(target, True, title)


BgpRib=BgpRib()

def bgpribRequireVpnRoutes(target, title, wantroutes, debug=0):
    BgpRib.RequireVpnRoutes(target, title, wantroutes, debug)

def bgpribRequireUnicastRoutes(target, afi, vrf, title, wantroutes, debug=0):
    BgpRib.RequireUnicastRoutes(target, afi, vrf, title, wantroutes, debug)
