OSPFv3 NSSA removal
==================

R2 is the only ABR: R1 attaches in Area 1, R3 in the backbone and R4 in
Area 2. R3 advertises a loopback used for real forwarding recovery checks.

Repeat normal -> NSSA -> normal under both summary policies. Inspect
self-originated Router-LSA Options E/N separately from the ASBR E flag.
Both the internal router and ABR must reoriginate normal capabilities
without an unrelated cost change. Removing one of two NSSAs must retain
ASBR status; removing the last must clear it when no redistribution
exists. Real static redistribution must retain ASBR status and an installed
external route across NSSA removal. Unused NSSA configuration must remove
cleanly. No daemon restart or running-configuration residue is permitted.

Protocol, route and forwarding convergence are awaited independently.
The test uses native configuration and ordinary protocol traffic only.
