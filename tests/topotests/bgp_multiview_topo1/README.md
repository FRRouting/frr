# Simple FreeRangeRouting Route-Server Test

## Topology
	+----------+ +----------+ +----------+ +----------+ +----------+
	|  peer1   | |  peer2   | |  peer3   | |  peer4   | |  peer5   |
	| AS 65001 | | AS 65002 | | AS 65003 | | AS 65004 | | AS 65005 |
	+-----+----+ +-----+----+ +-----+----+ +-----+----+ +-----+----+
	      | .1         | .2         | .3         | .4         | .5 
	      |     ______/            /            /   _________/
	       \   /  ________________/            /   /     
	        | |  /   _________________________/   /     +----------+  
	        | | |  /   __________________________/   ___|  peer6   |
	        | | | |  /  ____________________________/.6 | AS 65006 |
	        | | | | |  /  _________________________     +----------+
	        | | | | | |  /  __________________     \    +----------+ 
	        | | | | | | |  /                  \     \___|  peer7   |
	        | | | | | | | |                    \     .7 | AS 65007 |
	     ~~~~~~~~~~~~~~~~~~~~~                  \       +----------+
	   ~~         SW1         ~~                 \      +----------+
	   ~~       Switch           ~~               \_____|  peer8   |  
	   ~~    172.16.1.0/24     ~~                    .8 | AS 65008 |
	     ~~~~~~~~~~~~~~~~~~~~~                          +----------+
	              |
	              | .254
	    +---------+---------+
	    |       FRR  R1     |
	    |   BGP Multi-View  |
	    | Peer 1-3 > View 1 |       
	    | Peer 4-5 > View 2 |
	    | Peer 6-8 > View 3 |
	    +---------+---------+
	              | .1
	              |
	        ~~~~~~~~~~~~~        Stub Network is redistributed
	      ~~     SW0     ~~      into each BGP view with different
	    ~~   172.20.0.1/28  ~~   attributes (using route-map)
	      ~~ Stub Switch ~~
	        ~~~~~~~~~~~~~

## FRR Configuration

Full config as used is in r1 subdirectory

Simplified `R1` config:

	hostname r1
	!
	interface r1-stub
	 description Stub Network
	 ip address 172.20.0.1/28
	 no link-detect
	!
	interface r1-eth0
	 description to PE router - vlan1
	 ip address 172.16.1.254/24
	 no link-detect
	!
	bgp multiple-instance
	!
	router bgp 100 view 1
	 bgp router-id 172.30.1.1
	 network 172.20.0.0/28 route-map local1
	 timers bgp 60 180
	 neighbor 172.16.1.1 remote-as 65001
	 neighbor 172.16.1.2 remote-as 65002
	 neighbor 172.16.1.5 remote-as 65005
	!
	router bgp 100 view 2
	 bgp router-id 172.30.1.1
	 network 172.20.0.0/28 route-map local2
	 timers bgp 60 180
	 neighbor 172.16.1.3 remote-as 65003
	 neighbor 172.16.1.4 remote-as 65004
	!
	router bgp 100 view 3
	 bgp router-id 172.30.1.1
	 network 172.20.0.0/28
	 timers bgp 60 180
	 neighbor 172.16.1.6 remote-as 65006
	 neighbor 172.16.1.7 remote-as 65007
	 neighbor 172.16.1.8 remote-as 65008
	!
	route-map local1 permit 10
	 set community 100:9999 additive
	 set metric 0
	!
	route-map local2 permit 10
	 set as-path prepend 100 100 100 100 100
	 set community 100:1 additive
	 set metric 9999
	!

## Tests executed

### Check if FRR is running

Test is executed by running 

	vtysh -c "show log" | grep "Logging configuration for"
	
on router `R1`. This should return the logging information for all daemons registered
to Zebra and the list of running daemons is compared to the daemons started for this
test (`zebra` and `bgpd`)

### Verify for BGP to converge

BGP is expected to converge on each view within 60s total time. Convergence is verified by executing

	vtysh -c "show ip bgp view 1 summary"
	vtysh -c "show ip bgp view 2 summary"
	vtysh -c "show ip bgp view 3 summary"

and expecting 11 routes seen in the last column for each peer. (Each peer sends 11 routes)

### Verifying BGP Routing Tables

Routing table is verified by running 

	vtysh -c "show ip bgp view 1"
	vtysh -c "show ip bgp view 2"
	vtysh -c "show ip bgp view 3"

and comparing the result against the stored table in the r1/show_ip_bgp_view_NN.ref files
(with NN 1, 2, 3) (A few header and trailer lines are cut/adjusted ahead of the compare to
adjust for different output based on recent changes)

	
