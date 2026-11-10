OSPFv3 backbone Stub refusal
===========================

R1 -- Area 1 -- R2 -- Area 0 -- R3. R4 is an isolated configured OSPFv3
router with no areas. R3 advertises a loopback control prefix to R1.

Both dotted and decimal Area 0 IDs, with and without no-summary, must
produce a refusal diagnostic. Check running configuration, runtime area
type, absence of an accidentally created area on R4, Full neighbors,
neighbor state-change origins and ospf6d PIDs. Non-backbone Area 1 must
still accept both Stub forms, form Full neighbors and return to normal.

RFC 5340 Appendix C.2 forbids configuring the backbone as a Stub area.
The test uses only native configuration and ordinary protocol exchanges.
