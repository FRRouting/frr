# OSPFv2 (IPv4) Topology Test Unumbered (point-to-multipoint over Ethernet)

## Topology

	         SW1                        SW2
	\___________________/      \___________________/
	          |                          |
	          |                          |
	          | eth0:10.0.10.1/32        | eth0:10.0.20.1/32
	+---------+---------+      +---------+---------+
	|        R1         |      |        R2         |
	|     FRRouting     |      |     FRRouting     |
	| RID: 10.0.255.1   |      | RID: 10.0.255.2   |
	+---------+---------+      +---------+---------+
	          | eth1:10.1.1.2/32         | eth1:10.1.2.2/32
	           \______        ___________/
	                  \      /
	                   \    /
	             ~~~~~~~~~~~~~~~~~~
	           ~~       SW4        ~~
	         ~~       Switch         ~~
	           ~~                  ~~
	             ~~~~~~~~~~~~~~~~~~
	                     |
	                     | eth0:10.1.3.2/32 (unumbered)
	           +---------+---------+
	           |        R3         |
	           |     FRRouting     |
	           | RID: 10.0.255.3   |
	           +---------+---------+
	                     | eth0:10.0.30.1/24
	                     |
	             ~~~~~~~~~~~~~~~~~~
	           ~~       SW3        ~~
	         ~~       Switch         ~~
	           ~~                  ~~
	             ~~~~~~~~~~~~~~~~~~

## FRR Configuration

See full config from r1 / r2 / r3 subdirectories
