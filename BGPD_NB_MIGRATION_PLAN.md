# bgpd Northbound (YANG) Migration Plan

Tracks the work needed to make bgpd fully manageable via the FRR Northbound
(YANG-driven) management API, instead of `vtysh` + flat `bgpd.conf`. References
upstream tracking issue [FRRouting/frr#5428](https://github.com/FRRouting/frr/issues/5428).

This plan is written to be **picked up by agents working in parallel**. Each
phase is self-contained: it lists the files involved, the canonical pattern to
follow, acceptance criteria, and a verification recipe. An agent should be able
to read a single phase cold and ship it without needing the rest of the
document.

---

## 1. Goal

End state: every configuration knob in bgpd is reachable through the FRR
Northbound layer, which means:

- A YANG-aware client (mgmtd CLI, NETCONF, gRPC, gNMI, RESTCONF via translators)
  can read and write any BGP config that today requires `vtysh` or a textual
  `bgpd.conf`.
- Every config-mutating CLI command in `bgpd/*.c` goes through
  `nb_cli_enqueue_change()` + `nb_cli_apply_changes()`, never directly into
  internal `bgp_*` setters.
- `show running-config` is re-rendered from the YANG tree via registered
  `cli_show` callbacks, so the textual config is a faithful projection of the
  YANG datastore.
- bgpd registers its YANG modules with mgmtd as a backend client, declaring the
  XPaths it owns, so mgmtd routes config changes correctly.
- The full topotest suite (267+ `bgp_*` test directories, plus `mgmt_*` tests)
  continues to pass, and a new `mgmt_bgp_*` test family validates the
  YANG-driven path.

Out of scope: redesigning bgpd internals, changing on-wire BGP behavior, or
deprecating the legacy CLI surface. The legacy CLI keywords must remain
accepted; only their *plumbing* changes.

---

## 2. Current State (as of this plan)

Audited 2026-05-17 against `master` at commit `6fcf3ed92a`.

### 2.1 YANG models — mostly already written

11 BGP YANG files exist in `yang/`, totalling ~6,400 lines:

| File | Lines | Scope |
|---|---|---|
| `yang/frr-bgp.yang` | 1375 | Top-level container `bgp` under `/frr-rt:routing/control-plane-protocols/control-plane-protocol` |
| `yang/frr-bgp-common.yang` | 1330 | Global config groupings: MED, route-reflector, route-selection, timers, graceful-shutdown |
| `yang/frr-bgp-common-structure.yang` | 815 | Reusable groupings (EBGP multihop, capabilities, AFI/SAFI) shared between neighbor/peer-group |
| `yang/frr-bgp-common-multiprotocol.yang` | 208 | AFI/SAFI multipath, redistribution |
| `yang/frr-bgp-neighbor.yang` | 134 | `neighbors/neighbor` and `unnumbered-neighbor` lists |
| `yang/frr-bgp-peer-group.yang` | 99 | `peer-groups/peer-group` list |
| `yang/frr-bgp-types.yang` | 170 | Typedefs (as-type, peer-type, etc.) |
| `yang/frr-bgp-route-map.yang` | 1426 | Augments `frr-route-map` with BGP match/set conditions |
| `yang/frr-bgp-filter.yang` | 361 | Filter-list / prefix-list augmentations |
| `yang/frr-bgp-bmp.yang` | 204 | BMP collector/station/stats |
| `yang/frr-bgp-rpki.yang` | 210 | RPKI cache servers, validation knobs |
| `yang/frr-deviations-bgp-datacenter.yang` | 107 | Datacenter profile deviations |

**Top-level shape** (`frr-bgp.yang:91-284`):

```
/frr-rt:routing/control-plane-protocols/control-plane-protocol[type='frr-bgp:bgp']
  /bgp
    /global               leaf local-as; container confederation; container graceful-restart;
                          container afi-safis/afi-safi (multipath, redistribute, distance)
    /neighbors            list neighbor [remote-address];
                          list unnumbered-neighbor [interface]
    /peer-groups          list peer-group [peer-group-name]
```

This schema is **comprehensive in shape but not yet wired**. Audit during Phase 0
will check whether any per-knob leaves are still missing for things added since
the schema was last updated (EVPN MH knobs, BMP loc-rib, SRv6 service SIDs, BGP-LS
TLVs, conditional advertisement, recent `karthikeyav/bgpd-allowas-in-routemap`,
etc.) and add them rather than redesign.

### 2.2 Northbound callbacks — only route-map is wired

```
bgpd/bgp_routemap_nb.c          499 lines  module info + ~80 callback stubs
bgpd/bgp_routemap_nb.h          208 lines  declarations
bgpd/bgp_routemap_nb_config.c  3644 lines  create/modify/destroy for ~68 xpaths
```

`bgp_main.c:396-417` registers only `frr_bgp_route_map_info` (plus the
generic shared modules `frr_filter_info`, `frr_interface_info`,
`frr_route_map_info`, `frr_vrf_info`). The main `frr-bgp` module is **not
registered**. There is no `frr_bgp_info` struct, no `bgp_nb.c`, no
`bgp_nb_config.c`.

### 2.3 CLI inventory

```
bgpd/bgp_vty.c            422 commands  (377 config / 40 show / 5 clear)
bgpd/bgp_routemap.c       124 commands  (all config — partly NB)
bgpd/bgp_evpn_vty.c        97 commands  ( 47 config / 50 show)
bgpd/bgp_rpki.c            25 commands  ( 17 config / 6 show / 2 debug)
bgpd/bgp_debug.c           54 commands  ( 52 debug — out of scope)
bgpd/bgp_bmp.c             14 commands  ( 13 config / 1 show)
bgpd/bgp_flowspec_vty.c     3 commands
─────────────────────────────────────
Total                     ~739 commands; ~581 config-mutating
```

Only `bgp_routemap.c` (227 `nb_cli_enqueue_change` calls) and `bgp_rpki.c` (3
calls) currently flow through the NB layer. `bgp_vty.c` has **zero**
`nb_cli_enqueue_change` calls today — the largest single piece of work.

### 2.4 mgmtd integration

mgmtd uses dynamic XPath registration. The pattern (see `staticd/static_main.c:144-167`
and `mgmtd/mgmt_be_adapter.c:36-39,158-211,320-340`) is:

1. Daemon declares an array `static const char *const <daemon>_config_xpaths[]`
   of XPath prefixes it owns.
2. Daemon hands that to `mgmt_be_client_create("<daemon>", &cbs, 0, master)`
   inside `main()`.
3. mgmtd builds a `be_cfg_xpath_map[]` mapping XPath prefix → daemon bitmask.
4. When a frontend writes config, mgmtd routes each change to the owning daemon.

bgpd currently does not create an `mgmt_be_client`. Phase 1 adds this.

### 2.5 Tests

- **267 `bgp_*` topotest directories** under `tests/topotests/`. Most load
  `bgpd.conf` files and assert on `show ... json` (~925+ JSON assertions).
- **`tests/topotests/mgmt_tests/`, `mgmt_oper/`, `mgmt_startup/`, `mgmt_rpc/`** —
  exercise the mgmtd path and YANG datastore queries. These have hard-coded
  XPaths; any schema change requires updating them. Reference for the kind of
  churn to expect: commit `b36ebad54e` (staticd path-list key flattening)
  updated 8 XPath assertions in `mgmt_tests/test_yang_mgmt.py`.
- **`tests/bgpd/`** — C unit tests for aspath/community/packet parsing. **Not
  NB-related**; should not need changes.
- **CI** (`.github/workflows/github-ci.yml`) — runs the full topotest suite in
  parallel and re-runs failures once. Any churn in `show running-config`
  rendering will cascade through dozens of test fixtures.

---

## 3. Reference Pattern: how a single command converts

Use **staticd as the canonical small example** and **isisd as the canonical
large example**. Their layouts are identical:

```
<daemon>/<daemon>_nb.c          Module info (frr_<daemon>_info) + callback table
<daemon>/<daemon>_nb.h          XPath macros + callback declarations
<daemon>/<daemon>_nb_config.c   create/destroy/modify/pre_validate/apply_finish
<daemon>/<daemon>_nb_state.c    (isisd) operational-state getters
<daemon>/<daemon>_nb_notifications.c  (isisd) YANG notifications
<daemon>/<daemon>_cli.c         (isisd) — or `<daemon>_vty.c` (staticd) —
                                 DEFPY_YANG commands + cli_show callbacks
```

### 3.1 The five steps

Worked example: `ip route 10.0.0.0/24 192.168.1.1 distance 20` in staticd.

**(1) CLI command — `DEFPY_YANG`** in `staticd/static_vty.c:558-604` packs
arguments and delegates:

```c
DEFPY_YANG(ip_route_blackhole, ip_route_blackhole_cmd,
    "[no] ip route <A.B.C.D/M$prefix|...> <reject|blackhole>$flag ...", ...)
{
    struct static_route_args args = { .delete = !!no, .prefix = prefix, ... };
    return static_route_nb_run(vty, &args);
}
```

**(2) XPath construction + enqueue** in `static_route_nb_run()`
(`static_vty.c:94-514`):

```c
snprintf(xpath, sizeof(xpath),
    "/frr-routing:routing/control-plane-protocols/.../path-list"
    "[table-id='%u'][nh-type='%s'][vrf='%s'][gateway='%s']",
    ...);
nb_cli_enqueue_change(vty, xpath,            NB_OP_CREATE, NULL);
nb_cli_enqueue_change(vty, xpath "/distance", NB_OP_MODIFY, "20");
return nb_cli_apply_changes(vty, NULL);
```

**(3) NB callbacks** (`static_nb_config.c:295-346`) — invoked once per phase per
queued change:

```c
int routing_..._path_list_distance_modify(struct nb_cb_modify_args *args)
{
    switch (args->event) {
    case NB_EV_VALIDATE: return ecmp_path_list_validate(args);
    case NB_EV_PREPARE:  return NB_OK;
    case NB_EV_APPLY:
        nh = nb_running_get_entry(args->dnode, NULL, true);
        distance = yang_dnode_get_uint8(args->dnode, NULL);
        static_nexthop_move_path(nh, distance, nh->pn->metric);
        return NB_OK;
    case NB_EV_ABORT:    return NB_OK;
    }
}
```

Phases run for **every** queued change in this order:
`NB_EV_VALIDATE` → `NB_EV_PREPARE` → (`NB_EV_APPLY` | `NB_EV_ABORT`).
`apply_finish` fires once per parent xpath after all applies, for
post-commit fan-out (route table recompute, session reset, zclient updates).

**(4) Module registration** (`static_nb.c:15`):

```c
const struct frr_yang_module_info frr_staticd_info = {
    .name = "frr-staticd",
    .nodes = {
        { .xpath = ".../path-list",
          .cbs = { .create        = ..._create,
                   .destroy       = ..._destroy,
                   .pre_validate  = ..._pre_validate,
                   .apply_finish  = ..._apply_finish } },
        ...
    }
};
```

Added to the daemon's `<daemon>_yang_modules[]` array in `<daemon>_main.c`.

**(5) `cli_show` callback** renders the leaf back into `show running-config`:

```c
static void static_nexthop_cli_show(struct vty *vty, const struct lyd_node *dnode,
                                     bool show_defaults)
{
    vty_out(vty, "ip route %s via %s\n", prefix, gateway);
}
```

Registered alongside the modify callback on the same xpath node.

### 3.2 Coexistence during migration

bgpd already mixes converted (`bgp_routemap.c`) and unconverted (everything
else) command families. **This works** for end users of vtysh because old
DEFUNs still mutate internal state directly. But **changes via old DEFUNs are
invisible to mgmtd / NETCONF / gNMI clients**, because they never enter the
YANG datastore. This is acceptable mid-migration but is the central correctness
invariant we are trying to eliminate: a knob is "done" only when both the
running config and a NETCONF GET reflect changes made through either path.

There is no clean technical way to convert one DEFUN at a time inside a tightly
coupled command family (e.g., `neighbor X.X.X.X *`). The unit of conversion is
a logical YANG subtree (e.g., all of `/bgp/neighbors/neighbor`) plus every
CLI command that maps into it.

---

## 4. Phased Plan

Phases are ordered by dependency. **Phases 0–2 are sequential**; Phases 3a–3h
can be parallelised across agents once Phase 2 lands. Each phase below is
self-contained — an agent should be able to pick one up cold.

```
Phase 0  Schema audit & gap-fill                       (1 agent, ~1 week)
Phase 1  Wire the frr-bgp NB skeleton + mgmtd client   (1 agent, ~1 week)
Phase 2  Global BGP instance                           (1 agent, ~2 weeks)
Phase 3a Neighbor                                      (1 agent, ~4 weeks)
Phase 3b Peer-group                                    (1 agent, ~2 weeks; after 3a)
Phase 3c Address-family + per-AF knobs                 (1 agent, ~4 weeks; after 3a)
Phase 3d EVPN                                          (1 agent, ~2 weeks)
Phase 3e Flowspec / SRv6 / dampening                   (1 agent, ~1 week)
Phase 3f L3VPN / RT / RD                               (1 agent, ~2 weeks; after 3c)
Phase 3g BMP                                           (1 agent, ~1 week)
Phase 3h RPKI / BFD integration                        (1 agent, ~1 week)
Phase 4  Route-map completeness (close the 60% gap)    (1 agent, ~1 week)
Phase 5  cli_show rendering pass + snapshot cleanup    (1 agent, ~2 weeks)
Phase 6  mgmtd / NETCONF / gRPC integration tests      (1 agent, ~2 weeks)
Phase 7  Deviations: datacenter profile, deprecations  (1 agent, ~1 week)
```

Totals are rough engineer-weeks for an experienced FRR contributor, not wall
time. Phases 3a–3h can collapse to ~4 wall-weeks if run in parallel.

---

### Phase 0 — Schema audit and gap-fill

**Goal**: confirm every config command in `bgpd/*` has a corresponding YANG
leaf/container in `yang/frr-bgp*.yang`. Add what's missing **before** writing
any callbacks.

**Inputs**:
- All `DEFPY*`/`DEFUN*` in `bgpd/bgp_vty.c`, `bgp_evpn_vty.c`,
  `bgp_flowspec_vty.c`, `bgp_bmp.c`, `bgp_rpki.c`.
- All existing leaves in `yang/frr-bgp*.yang`.

**Method**:
1. Build a flat list of every config-mutating command keyword path
   (e.g., `router bgp ASN`, `bgp router-id A.B.C.D`,
   `neighbor X.X.X.X remote-as ASN`, `address-family ipv4 unicast`,
   `redistribute connected`, ...). Tool suggestion: `grep -nE 'DEF(PY|UN)' bgpd/*.c`
   + a small Python script that strips the cmd-string.
2. For each, locate the corresponding YANG node. If missing, add the leaf to the
   appropriate `frr-bgp*.yang` file using existing groupings. Do **not**
   restructure existing nodes — only add.
3. Pay special attention to recent additions: `bgp_conditional_adv.c`,
   `bgp_ls.c` / `bgp_ls_nlri.c` / `bgp_ls_ted.c`, `bgp_attr_srv6.h`,
   `bgp_community_alias.c`, `bgp_bfd.c`, EVPN MH (`bgp_evpn_mh.c`), allowas-in
   in route-maps (recent PR `#20659`).

**Deliverable**: a PR titled `bgpd, yang: fill gaps in frr-bgp YANG schema`
containing **only** YANG additions plus the audit script in
`tools/audit_bgp_yang.py` (so we can re-run it as new commands land).

**Acceptance**:
- `python3 tools/audit_bgp_yang.py` reports zero unmapped commands.
- `make check_yang` passes (validates YANG syntax + module load).
- No regressions in `tests/topotests/` (we haven't wired anything yet —
  this is a pure schema PR).

---

### Phase 1 — Skeleton: register frr-bgp with NB and mgmtd

**Goal**: stand up empty NB plumbing so subsequent phases can attach
callbacks one knob at a time.

**Files to create**:
- `bgpd/bgp_nb.c` — defines `frr_bgp_info` (initially with an empty `.nodes[]`).
- `bgpd/bgp_nb.h` — header with XPath macros (`#define BGP_XPATH_INSTANCE
  "/frr-routing:routing/.../control-plane-protocol[type='frr-bgp:bgp']..."`).
- `bgpd/bgp_nb_config.c` — empty file ready for callbacks.

**Files to edit**:
- `bgpd/bgp_main.c:396-417` — add `&frr_bgp_info` to `bgpd_yang_modules[]`.
- `bgpd/bgp_main.c` (around `frr_run()`) — add the mgmtd backend client:

  ```c
  static const char *const bgpd_config_xpaths[] = {
      "/frr-host:host",
      "/frr-logging:logging",
      "/frr-vrf:lib",
      "/frr-interface:lib",
      "/frr-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='frr-bgp:bgp']",
      "/frr-route-map:lib/route-map/.../frr-bgp-route-map:*",
      "/frr-filter:lib",
  };

  static struct mgmt_be_client_cbs bgpd_be_client_data = {
      .config_xpaths  = bgpd_config_xpaths,
      .nconfig_xpaths = array_size(bgpd_config_xpaths),
  };

  /* in bgp_master_init or equivalent */
  mgmt_be_client = mgmt_be_client_create("bgpd", &bgpd_be_client_data, 0, bm->master);
  ```

- `bgpd/subdir.am` — add the new files to the build.
- `mgmtd/mgmt_be_adapter.c` — verify the daemon name `bgpd` is recognized; add
  it to the `MGMTD_BE_CLIENT_*` enum/array if hardcoded list exists.

**Acceptance**:
- bgpd starts cleanly, connects to mgmtd, and `vtysh -c "show mgmt
  backend-adapter all"` lists `bgpd` with its XPath subscriptions.
- All existing topotests pass — no functional change.
- A trivial mgmtd write to `/frr-routing:routing/.../bgp/global/local-as` is
  routed to bgpd (it will error because no callback exists; that's expected).

---

### Phase 2 — Global BGP instance

**Scope**: the `router bgp ASN [vrf NAME | view NAME]` context and every
direct child of `bgp global`:
- `bgp router-id`, `bgp cluster-id`, `bgp confederation identifier|peers`
- `bgp bestpath ...`, `bgp default ...`
- `bgp graceful-restart ...`, `bgp graceful-shutdown`, `bgp update-delay`
- `bgp listen limit|range`
- `bgp coalesce-time`, `bgp max-med`, `bgp deterministic-med`
- `bgp log-neighbor-changes`, `bgp suppress-fib-pending`
- Global timers: `timers bgp keepalive holdtime`

YANG anchor: `/frr-rt:routing/.../bgp/global` (`yang/frr-bgp.yang`,
`yang/frr-bgp-common.yang`).

**Pattern for this phase** (worked example: `bgp router-id 1.1.1.1`):

1. In `bgp_nb_config.c`, implement:
   - `..._bgp_global_router_id_modify(struct nb_cb_modify_args *)`
   - `..._bgp_global_router_id_destroy(struct nb_cb_destroy_args *)`

   In `NB_EV_APPLY`, call the existing internal setter
   (`bgp_router_id_static_set()` or whatever `bgp_vty.c` calls today) instead of
   reimplementing it. This minimises behavioural risk.

2. In `bgp_nb.c`, register the xpath + callbacks in `frr_bgp_info.nodes[]`.

3. In `bgp_vty.c`, find the existing `DEFUN(bgp_router_id, ...)`. Rewrite it as
   `DEFPY_YANG` that calls:

   ```c
   nb_cli_enqueue_change(vty, "./router-id", NB_OP_MODIFY, router_id_str);
   return nb_cli_apply_changes(vty,
       "/frr-routing:routing/control-plane-protocols/"
       "control-plane-protocol[type='frr-bgp:bgp']"
       "[name='bgp'][vrf='%s']/frr-bgp:bgp/global", vrf_name);
   ```

4. Add a `cli_show` callback for that xpath rendering `bgp router-id X.X.X.X`.

5. Repeat for every leaf in `bgp/global/*`.

**File budget** (estimate):
- `bgp_nb.c`: +~300 lines (node registrations)
- `bgp_nb_config.c`: +~1500 lines (callbacks)
- `bgp_vty.c`: ~30 DEFUN→DEFPY_YANG rewrites; net +200 / -300 lines

**Acceptance**:
- All existing `bgp_*` topotests pass.
- New `tests/topotests/mgmt_bgp_global/` exercises every leaf in `bgp/global`
  through mgmtd (set via mgmtd, read via `show running-config`, assert match).
- `vtysh -c "show running-config bgpd"` byte-identical to pre-conversion
  for the same input config (checked via the round-trip test added in this
  phase — see §5.2).

---

### Phase 3a — Neighbor

**Scope**: every `neighbor X.X.X.X *` and `neighbor INTERFACE *` command. This
is the largest single chunk (~180 commands).

YANG anchor: `/frr-rt:routing/.../bgp/neighbors/neighbor` and
`unnumbered-neighbor` (`yang/frr-bgp-neighbor.yang`,
`yang/frr-bgp-common-structure.yang`).

**Critical design decisions**:

1. **Session reset semantics**. Some leaf modifies require BGP session reset
   (e.g., `remote-as` change, `password` change). Today this happens
   side-effect-of-CLI inside `bgp_vty.c`. Move the reset into the
   `apply_finish` callback registered on
   `/bgp/neighbors/neighbor[remote-address=X]`, so it fires once per neighbor
   per transaction even when multiple leaves change atomically. **Do not** call
   reset from individual `_modify` callbacks — that would cause N resets for an
   N-leaf change.

2. **Validation that crosses leaves** (e.g., `remote-as` must exist before
   `ebgp-multihop`). Use `pre_validate` on the neighbor list entry, which fires
   once before any per-leaf validate, and has visibility into the candidate
   config in full.

3. **Inherited-from-peer-group leaves**. YANG can't express "this leaf is
   inherited unless overridden" cleanly. Keep two leaves: `value` (explicit) and
   a derived `effective-value` exposed only in operational state (Phase 6).
   `cli_show` only emits the explicit one.

**File budget** (estimate):
- `bgp_nb_config.c`: +~5000 lines (~80 leaves × ~60 lines avg)
- `bgp_nb.c`: +~600 lines
- `bgp_vty.c`: ~180 DEFUNs rewritten

**Acceptance**:
- All `bgp_*` topotests pass.
- New `tests/topotests/mgmt_bgp_neighbor/` covers add/modify/delete of a
  neighbor with every leaf set/unset, plus round-trip
  `set → show running → reload → show running → diff == ø`.
- Manually verify: `vtysh -c "no neighbor 1.2.3.4 remote-as 65001"` and
  mgmtd `delete /bgp/neighbors/neighbor[remote-address='1.2.3.4']` produce
  the same end state.

---

### Phase 3b — Peer-group

**Depends on**: Phase 3a (neighbor knob set must exist first because
peer-group leaves reuse the same `frr-bgp-common-structure` groupings).

**Scope**: `neighbor PG peer-group`, `neighbor X.X.X.X peer-group PG` (the
membership leaf on the neighbor side is part of 3a; this phase covers the
peer-group object itself), and every `neighbor PG <leaf>` that mirrors a
neighbor leaf.

YANG anchor: `/frr-rt:routing/.../bgp/peer-groups/peer-group`
(`yang/frr-bgp-peer-group.yang`).

**Pattern**: reuse the same `_modify` callback bodies as 3a wherever the
internal setters accept either a `peer` or a `peer_group` (most do, via
`peer_group_active(peer)` checks). Keep the YANG schema parallel — same leaf
names under both lists.

**Acceptance**: peer-group `set X` propagates to all member neighbors;
unsetting a peer-group leaf restores the member's overridden or default value
(must be tested explicitly — this is where most peer-group bugs live).

---

### Phase 3c — Address-family + per-AF knobs

**Depends on**: Phase 3a.

**Scope**: the `address-family <afi> <safi>` context plus all
per-(neighbor, AF) and per-(BGP instance, AF) knobs:
- `network`, `aggregate-address`
- `redistribute <proto>`
- `neighbor X activate / deactivate`
- `neighbor X route-map`, `prefix-list`, `filter-list`, `distribute-list`
- `neighbor X maximum-prefix`, `maximum-prefix-out`
- `neighbor X next-hop-self`, `route-reflector-client`, `route-server-client`
- `neighbor X soft-reconfiguration inbound`, `send-community`,
  `remove-private-as`
- `maximum-paths`, `bgp distance`

YANG anchor: `/frr-rt:routing/.../bgp/global/afi-safis/afi-safi[afi-safi-name]`
and the parallel per-neighbor `neighbor/afi-safis/afi-safi[afi-safi-name]`.

**Critical decision**: CLI is hierarchical (`router bgp → address-family →
neighbor activate`) but YANG xpath is flat. The CLI command's `nb_cli_apply_changes`
needs to know the *current* `address-family` context. Use `VTY_CHECK_CONTEXT` /
`VTY_GET_CONTEXT` patterns already in `bgp_vty.c`. The xpath prefix passed to
`nb_cli_apply_changes(vty, fmt, ...)` includes the AF key.

**File budget** (estimate):
- `bgp_nb_config.c`: +~4000 lines
- `bgp_vty.c`: ~140 DEFUN rewrites

---

### Phase 3d — EVPN

**Files**: `bgpd/bgp_evpn_vty.c` (47 config commands), `bgpd/bgp_evpn_mh.c`,
`bgpd/bgp_evpn.c`.

**YANG**: extend `frr-bgp.yang` or carve a new `frr-bgp-evpn.yang` augmenting
`bgp/global/afi-safis/afi-safi[afi-safi-name='l2vpn-evpn']`. Phase 0 should
have decided which.

**Specific knobs**: VNI, advertise-all-vni, default-gw, svi-ip,
advertise-svi-ip, RD/RT (import/export), type-5 prefix, auto-rt,
flooding head-end, EAD options, MH (`evpn mh es-...`), duplicate-address-detection.

Self-contained — does not depend on 3c if 3c shipped the AF context entry.

---

### Phase 3e — Flowspec / SRv6 / dampening

`bgpd/bgp_flowspec_vty.c`, `bgp_damp.c`, SRv6-related DEFUNs in `bgp_vty.c`
(`bgp_attr_srv6.h`, locator/binding/transposition).

YANG: small additions to `frr-bgp-common.yang`. Most flowspec config is
operational/advertised rather than configured directly.

---

### Phase 3f — L3VPN / RT / RD

**Depends on**: Phase 3c (address-family context).

`address-family vpnv4|vpnv6 unicast`, `rd vpn export`, `rt vpn import|export`,
`route-map vpn import|export`, `import vrf`, `label vpn export`.

This is the trickiest knob family for transactional validation: changing an RT
on one VRF can affect imports on every other VRF. Use `apply_finish` on the
`bgp/global` node (above all AFs) to trigger one re-leak pass per transaction.

---

### Phase 3g — BMP

`bgpd/bgp_bmp.c` (13 config commands). YANG model exists in
`yang/frr-bgp-bmp.yang`. Small scope; good warm-up phase for a new contributor.

---

### Phase 3h — RPKI / BFD integration

`bgpd/bgp_rpki.c` (17 config; 3 already use NB), `bgpd/bgp_bfd.c`.

RPKI partial conversion in `bgp_rpki.c` should be completed (close the gap to
the schema in `yang/frr-bgp-rpki.yang`).

BFD config on a neighbor is a `neighbor X bfd ...` family — coordinate with
Phase 3a if not yet shipped.

---

### Phase 4 — Route-map completeness

**Scope**: `bgpd/bgp_routemap.c` already has 227 `nb_cli_enqueue_change`
calls — but `frr-bgp-route-map.yang` is 1426 lines. Audit the gap.

**Specifically check**: recently merged `karthikeyav/bgpd-allowas-in-routemap`
(PR `#20659`) — does it have a corresponding YANG leaf in `frr-bgp-route-map.yang`
and a `bgp_routemap_nb_config.c` callback? Likely no.

This phase is essentially "audit-then-fill", parallel to Phase 0 but for the
route-map subtree.

---

### Phase 5 — `cli_show` rendering pass + snapshot cleanup

By this point every config knob writes through NB. The remaining risk is that
`show running-config` no longer byte-matches what it used to. Each phase
should have caught regressions in its own area, but ordering / whitespace
across the full file is best fixed in one pass.

**Method**:
1. Take a representative bgpd.conf (use a few large topotest configs).
2. Diff `vtysh -c "show running-config"` against the input file. Iterate on
   `cli_show` callbacks until the diff is empty modulo intentional
   normalisation (sorted neighbors, etc.).
3. Update topotest fixtures *only* where the new rendering is provably
   semantically equivalent. Where tests assert on specific lines, prefer
   updating the assertion over re-introducing legacy ordering.

**Output**: a single PR with the cli_show polish + the test fixture diffs.
Reviewer should be able to see "format-only changes" at a glance.

---

### Phase 6 — mgmtd / NETCONF / gRPC integration tests

New topotest directories:
- `tests/topotests/mgmt_bgp_smoke/` — bring up two routers via mgmtd-only
  config (no `bgpd.conf`); verify session establishes.
- `tests/topotests/mgmt_bgp_roundtrip/` — for every YANG leaf, set via mgmtd,
  read via `vtysh show running-config`, assert match; then save, reload,
  assert match again. Generated, not hand-written.
- `tests/topotests/mgmt_bgp_oper/` — operational state queries (Phase 6
  alternative if we ship op-state in this phase).
- `tests/topotests/grpc_bgp/` — exercise the gRPC frontend with a few
  representative writes/reads.

Reuse helpers in `tests/topotests/lib/topogen.py` and the patterns from
`tests/topotests/mgmt_tests/test_yang_mgmt.py`. The schema-flattening churn
seen in commit `b36ebad54e` is a good template for what test updates look
like.

---

### Phase 7 — Deviations: datacenter profile, deprecations

`yang/frr-deviations-bgp-datacenter.yang` already exists but may be stale.
Re-validate it against the new callback set. Identify any CLI commands that
should be marked `deprecated` in YANG (commands kept for back-compat but no
longer recommended).

Also: file an upstream tracking comment on issue #5428 documenting the
completed migration.

---

## 5. Test Strategy

The migration must keep the **267 `bgp_*` topotests + the `mgmt_*` topotests +
the `tests/bgpd/` C unit tests** green throughout. Strategy:

### 5.1 Standing invariants (never break)

- Every CLI command that was accepted before is still accepted, with the same
  optional tokens.
- `bgpd.conf` files that worked before still parse and load.
- `show ... json` output structure is unchanged (operational, not touched).
- SIGHUP-driven reload behaves identically.

### 5.2 New invariants we add

- **Round-trip**: for every config in `tests/topotests/bgp_*/r*/bgpd.conf`,
  loading the config, dumping `show running-config`, parsing the dump, and
  loading it again must converge byte-for-byte after one round. Add a
  generated topotest `tests/topotests/bgp_roundtrip_all/` that asserts this
  for every existing fixture.
- **CLI-vs-NETCONF equivalence**: for each YANG leaf, asserts that setting it
  via vtysh and setting it via mgmtd produce the same `show running-config`
  output. Generated from the YANG schema in Phase 6.

### 5.3 Per-phase test discipline

Every phase ships with:
- Its own `tests/topotests/mgmt_bgp_<phase>/` directory exercising the leaves
  it just converted.
- A run of the *entire* `bgp_*` topotest tree green in CI before merge.
- If a test fails because the cli_show format changed, the test fixture is
  updated **in the same PR**, with the diff clearly justified in the commit
  message. Reviewers should be able to see test-fixture changes side-by-side
  with the cli_show callback that caused them.

### 5.4 Snapshot churn budget

Based on `b36ebad54e` precedent (8 XPath updates for a single staticd
flattening), expect roughly:
- **~40–60 fixture updates total** across the full migration, mostly in
  `tests/topotests/mgmt_*` (XPath-sensitive) and `tests/topotests/bgp_*` (cli
  ordering-sensitive).
- Concentrate the churn in Phase 5 by deferring cli_show polish until the
  end. Each Phase 3 PR can ship "good enough" cli_show; Phase 5 makes it
  pixel-perfect.

### 5.5 Tools to add

- `tools/audit_bgp_yang.py` (Phase 0) — maps CLI commands to YANG xpaths;
  reports unmapped commands. Re-run as new commands land.
- `tools/audit_bgp_nb.py` (Phase 1+) — for every YANG leaf, asserts a
  callback is registered. Re-run before each Phase-3 PR.
- `tools/bgp_roundtrip.py` (Phase 5) — runs the round-trip diff on every
  fixture and reports breakage. Wired into CI.

---

## 6. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| `cli_show` rendering drifts from legacy `show running-config` ordering, cascading test failures across hundreds of `bgp_*` topotests | High | High | Phase 5 dedicated to format polish; round-trip CI test catches drift early |
| Session-reset side-effects fire too often or too rarely when many leaves change atomically | Medium | High | Centralise reset in per-neighbor `apply_finish`; test explicitly with multi-leaf transactions |
| YANG schema flattening / restructure mid-migration breaks all hardcoded XPath tests | Medium | Medium | Lock the YANG schema at end of Phase 0; subsequent phases only add leaves, never restructure |
| Peer-group inheritance semantics (override / inherit / default) don't fit cleanly into YANG | Medium | Medium | Keep two leaves (`value` + derived `effective-value`); decided in Phase 3a |
| L3VPN cross-VRF transactional validation (RT changes affecting multiple VRFs) hard to express | Low | High | Use `apply_finish` at `bgp/global` level for one re-leak pass; tested with multi-VRF topotest |
| mgmtd doesn't currently recognise bgpd as a backend client; protocol mismatches | Low | High | Phase 1 explicitly verifies adapter handshake before any callback work |
| Old DEFUN commands and new NB-driven commands write to the same internal state inconsistently during migration | Medium | Medium | This is the steady-state pain. Document clearly in each Phase 3 PR which subtrees are now NB-owned; CI test asserts no DEFUN in those areas. |
| Recent PRs (e.g., #20659 allowas-in-routemap) added knobs not in the schema | High | Low | Phase 0 audit + a recurring CI gate using `tools/audit_bgp_yang.py` |
| Performance regression: NB transaction overhead on large configs (10k neighbors) | Low | Medium | Benchmark in Phase 5 against pre-conversion baseline; mgmtd already handles this for staticd at scale |

---

## 7. How to Pick Up This Plan

Agents should:

1. Open `TaskList` and look for a phase labelled `bgpd-nb:<phase>` not yet
   `in_progress`.
2. Read this document's **§3 Reference Pattern** + the phase section.
3. Read the equivalent code in `staticd/static_nb*.c` (small) or
   `isisd/isis_nb*.c` (large) as a worked example before writing any code.
4. Run `tools/audit_bgp_yang.py` and `tools/audit_bgp_nb.py` (after Phase 0/1)
   to scope the phase.
5. Open a PR titled `bgpd, yang, nb: <phase name>` and reference issue
   `FRRouting/frr#5428` in the description.

If a phase's scope is larger than ~3000 LOC after audit, split it along YANG
sub-container boundaries (e.g., split Phase 3a into "neighbor base" +
"neighbor capabilities" + "neighbor timers"). Never split mid-DEFUN.

---

## 8. Open Questions to Resolve Before Phase 0 Begins

1. **Schema versioning**: do we bump the `frr-bgp` YANG module's `revision`
   for every Phase 3 PR, or once at the end of Phase 5? FRR project policy is
   usually per-revision-per-add; confirm with maintainers.
2. **Operational state**: is Phase 6 the right time to ship op-state getters
   (`*_nb_state.c`) for `show bgp summary`, `show bgp neighbors`, etc., or
   defer to a separate epic? Recommend deferring — it's a parallel concern.
3. **Removal of legacy DEFUNs**: do we ever delete the legacy DEFUN, or keep
   the YANG-routed DEFPY_YANG forever? Recommend keeping — the user's CLI
   surface should not change.
4. **gRPC schema**: do we need to ship a `.proto` for the BGP YANG model, or
   does mgmtd's existing generic schema-walk gRPC suffice? Investigate in
   Phase 6.

Resolve these before Phase 0 starts work, ideally with a comment on issue
`#5428` requesting upstream guidance.
