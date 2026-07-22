# BGP YANG Northbound — Key Design Freeze

Date: 2026-07-21

## Instance identity

BGP instances map to `frr-routing` control-plane-protocol list entries:

```
/frr-routing:routing/control-plane-protocols/control-plane-protocol
  [type='frr-bgp:bgp'][name='NAME'][vrf='VRF']
    /frr-bgp:bgp
      /global/...
```

| CLI | `name` key | `vrf` key | `instance-type-view` |
|-----|------------|-----------|----------------------|
| `router bgp AS` | `default` (or VRF_DEFAULT_NAME) | VRF_DEFAULT_NAME | false |
| `router bgp AS vrf NAME` | NAME | NAME | false |
| `router bgp AS view NAME` | NAME | NAME | true |

Mandatory leaf: `/frr-bgp:bgp/global/local-as` (set on create with the AS).

Optional on create: `/global/as-notation`, `/global/instance-type-view`.

## Neighbor lists

| Kind | List key | XPath under `/frr-bgp:bgp` |
|------|----------|----------------------------|
| Numbered | `remote-address` | `neighbors/neighbor` |
| Unnumbered | `interface` | `neighbors/unnumbered-neighbor` |
| Peer-group | `peer-group-name` | `peer-groups/peer-group` |

## AFI/SAFI

Keyed list `afi-safis/afi-safi[afi-safi-name]` using `frr-routing` AFI/SAFI identities (`ipv4-unicast`, `l2vpn-evpn`, `link-state`, …).

## Optional modules

| Module | When registered |
|--------|-----------------|
| `frr-bgp` | Always (core) |
| `frr-bgp-route-map` | Already registered |
| `frr-bgp-filter` | With filter conversion |
| `frr-bgp-rpki` | With RPKI conversion |
| `frr-bgp-vnc` | Only if `--enable-vnc`; enable YANG feature `vnc` |

## Inheritance rule

YANG stores **explicit** peer/peer-group configuration only. Runtime inherit/override remains in existing `PEER_FLAG_*` / peer-group C APIs. `cli_show` must suppress inherited values like today's `bgp_config_write_peer`.

## bgpyang WIP note

`remotes/bgpyang/*` uses module name `frr-bgpd` and leaf `is-view`. Master schemas use **`frr-bgp`** and **`instance-type-view`**. Do not copy WIP XPaths verbatim; adapt helpers to master YANG.

## Config CLI conversion status (2026-07-22)

Daemon-local NB **configuration** CLI conversion for BGP is effectively
complete for vertical slices covered by this effort (globals, neighbors,
AFI/SAFI, filters, RPKI, interface MPLS, VNC when enabled, SNMP trap knobs).

Inventory: regenerate `yang/BGP_YANG_CLI_GAP.{csv,md}` with
`python3 yang/tools/extract_bgp_cli_config.py`. Prefer the
**CONVERTED** / **INTENTIONAL** columns over older MISSING heuristics —
commands defined with `DEFUN_YANG` / `DEFPY_YANG` are already on NB even
when path matching was wrong.

**Intentionally left classic**

- `exit-address-family` (node exit)
- Hidden `bgp local-mac`
- EVPN test helpers (`evpnrt5`, `test_es_*`)
- `rpki reset` (operational reset in RPKI config mode, not NB config)
- Debug / show / clear / dump (out of scope)

**Follow-ups (not blocking “config done”)**

- Drop dual-path classic `config_write` once YANG `cli_show` is trusted
  (started: RPKI node / VRF hook; daemon-wide `/frr-bgp:bgp-daemon` knobs
  including SNMP traps and community aliases)
- Ops (debug/show/clear) remain classic by design
- Do not YANG-convert `rpki reset` as configuration
- Remaining classic writers: `bgp_config_write` (per-instance globals /
  neighbors / AF), filters (as-path / community-list need `cli_show`),
  VNC nodes, dump/debug
