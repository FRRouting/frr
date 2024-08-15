.. _bmp:

***
BMP
***

RFC 7854: BMP Adj-RIB-In
========================
Missing features (non exhaustive):
  - Peer Down
    - Reason codes (according to TODO comments in code)

RFC 9069: BMP Local-RIB
=======================
Everything that isn't listed here is implemented and should be working.
Missing features (should be exhaustive):

- Peer Down Only
  - Reason code (bc not supported in RFC 7854 either)

RFC8671: BMP Adj-RIB-Out
========================
Adj-RIB-Out pre-policy monitoring uses tricks to work because soft-reconfiguration outbound does not exist.
So what we do is we call the BGP function (subgroup_announce_check) which decides whether to announce or not to peers,
while ignoring the outbound policy + some conditions specific to Adj-RIB-Out Post-policy.
This allows us to guess whether the route would've been in Adj-RIB-Out Pre-policy or not. However, we cannot compute
all pre-policy stats as a consequence.

Everything that isn't listed here is implemented and should be working.

- Per-Peer Header
    - Timestamp: not recorded, set to 0

- Stats
    - adj-rib-out pre-policy counters (cannot be done since adj-rib-out pre-policy is not saved)

ECMP Support
============
The RX Add-Path ID is exported for Adj-RIB-In Pre/Post-policy and Local-RIB.
The TX Add-Path ID is exported for Adj-RIB-Out Pre/Post-policy.
