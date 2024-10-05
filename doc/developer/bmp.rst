.. _bmp:

***
BMP
***

RFC 7854
========
Missing features (non exhaustive):
  - Per-Peer Header

    - Peer Type Flag
    - Peer Distingsher

  - Peer Up

    - Reason codes (according to TODO comments in code)

Peer Type Flag and Peer Distinguisher can be implemented easily using RFC 9069's base code.

RFC 9069
========
Everything that isn't listed here is implemented and should be working.
Missing features (should be exhaustive):

- Per-Peer Header

  - Timestamp

    - set to 0
    - value is now saved `struct bgp_path_info -> locrib_uptime`
    - needs testing

- Peer Up/Down

  - VRF/Table Name TLV

    - code for TLV exists
    - need better RFC understanding

- Peer Down Only

  - Reason code (bc not supported in RFC 7854 either)

- Statistics Report

  - Stat Type = 8: (64-bit Gauge) Number of routes in Loc-RIB.
  - Stat Type = 10: Number of routes in per-AFI/SAFI Loc-RIB. The value is
    structured as: 2-byte AFI, 1-byte SAFI, followed by a 64-bit Gauge.
