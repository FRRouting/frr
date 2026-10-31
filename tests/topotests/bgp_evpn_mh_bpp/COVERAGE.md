# EVPN Bridge-Port Protection Test Traceability

## Purpose

This document maps the FRRouting (FRR) bridge-port protection requirements
and externally visible behavior to automated tests. It is a coverage audit,
not a claim that FRR topotests validate the complete SONiC data path.

The audit uses these source-of-truth documents:

- `EVPN-Bridge-Port-Protection-FRR-HLD.md`, especially Sections 6 and 16
- `BridgePort_Protection_FRR_Dev_Plan.md`, especially Sections 4, 5, and
  Phase 13
- `BridgePort_Protection_FPM_Contract.md`

Those documents are maintained in the companion `sonic_hld` repository under
`BridgePortProtectionGroup-frr/doc/vxlan/EVPN/`.

Where the documents conflict, the frozen FPM contract takes precedence over
older HLD or development-plan text. This audit therefore expects Member tag
4, Group tag 8, native ABI layouts, and fixed FPM message numbers 147–153.
The same-lifetime ID retirement rule also follows the newer HLD/FPM contract;
the older development-plan language that permits reuse after acknowledgement
must be reconciled.

The implementation snapshot audited here is commit `57ace6e392`.

## Status legend

| Status | Meaning |
|---|---|
| **Covered** | A normal automated FRR test directly asserts the requirement. |
| **Partial** | FRR behavior is tested, but wire-level, consumer, restart, or hardware behavior remains outside that test. |
| **External** | The requirement belongs to SONiC or requires an actual `dplane_fpm_sonic`/ASIC environment. |
| **Deferred** | Explicitly outside the initial release. |
| **Pending** | Required evidence has not yet been collected or automated. |

## Validation snapshot

| Validation | Result |
|---|---|
| BPP topotest | **Covered** — 93 passed, 1 skipped in 301.18 seconds |
| L3MH regression | **Covered** — 58 passed in 375.44 seconds |
| BPP feature tests | 90 `test_bpp_*` tests |
| Baseline topology tests | 3 tests |
| Memory leak test | **Pending** — present, but skipped unless memory-leak reporting is enabled |
| FRR build | **Covered** |
| Checkpatch | **Covered** — 0 errors, 0 warnings |
| Changed-line coverage above 80% | **Pending** — no coverage report captured |
| Full FRR CI / all existing EVPN suites | **Pending** — local BPP and L3MH suites passed; full CI is still required |

## Requirements traceability matrix

### Configuration, state, and observability

| ID | Requirement or functionality | Automated evidence | Status | Residual risk |
|---|---|---|---|---|
| CFG-01 | Protection is configured per ES bond with `evpn mh bridge-port-protection`; configuration persists through the northbound model and running configuration. | `test_bpp_config` | **Covered** | None identified in FRR. |
| CFG-02 | An unconfigured ES exports no protection objects. | `test_bpp_unprotected_l3mh_es`, `test_bpp_dplane_emit` cleanup | **Covered** | None identified in FRR. |
| CFG-03 | Configuration before its dependencies is retained as `PENDING`; no partial Binding is exported. | `test_bpp_pending_reasons`, `test_bpp_es_evi_pending_es`, `test_bpp_pending_vlan` | **Partial** | No direct test covers `no SVI or IP-VRF`, `L3VNI down`, all simultaneous reasons, or an entirely pending ES with an explicit no-Binding assertion. |
| CFG-04 | Configuration order is insignificant and reconciliation occurs when dependencies appear. | `test_bpp_entries`, `test_bpp_es_evi_l3vni_order`, `test_bpp_eligibility_order`, `test_bpp_new_local_vrf` | **Covered** | None identified in tested dependency orders. |
| CFG-05 | Removing protection deletes the Binding, Group, and unreferenced Members. | `test_bpp_disable`, `test_bpp_protection_off_del` | **Covered** | SONiC consumption of those deletes is external. |
| CFG-06 | Removing the ES performs the same complete cleanup. | `test_bpp_es_delete` | **Covered** | SONiC consumption is external. |
| STATE-01 | Zebra maintains one protection entry per VLAN on the protected bond. | `test_bpp_entries`, `test_bpp_scale` | **Covered** | VLAN subinterfaces are explicitly unsupported. |
| STATE-02 | VLAN readiness follows a valid local IP-VRF/L3VNI association. | `test_bpp_pending_reasons`, `test_bpp_es_vrf_assoc`, `test_bpp_vrf_leaves_ready_set` | **Covered** | None identified in FRR. |
| STATE-03 | SVI and local access-link operational state do not remove the protection intent or exported backup objects. | `test_bpp_link_state`, `test_bpp_ip_ead_tx_svi_oper`, `test_bpp_local_link_down` | **Partial** | Access-link export preservation is direct; the SVI test checks RT-1 stability but not a snapshot of every exported object. Hardware switchover is external. |
| STATE-04 | L3MH mode (`l3vni-neigh`) gates L3VNI ES-EVI and IP A-D behavior. | `test_bpp_l3mh_gate`, `test_bpp_ip_ead_tx_no_l3mh`, `test_bpp_ip_ead_rx_knob_off`, `test_bpp_knob_off_del` | **Covered** | None identified in FRR. |
| STATE-05 | A BD becoming an L2VNI is not treated as an L3MH protected BD. | `test_bpp_l3mh_bd_gets_l2vni`, `test_bpp_l2vni_on_bd_binding` | **Covered** | Mixed L2VNI/L3VNI protection is deferred. |
| STATE-06 | Show table, interface/detail filters, member view, pending reasons, export status, and JSON output are available and consistent. | `test_bpp_show`, `test_bpp_show_member`, `test_bpp_export_status` | **Partial** | `test_bpp_export_status` does not first require every expected VLAN to be ACTIVE; last FPM error visibility is not failure-injected. |
| STATE-07 | Zebra and bgpd protection debug controls and event/reason logging work. | `test_bpp_debug` plus eligibility tests that inspect logs | **Partial** | Some log checks are not isolated by a sequence marker and can match stale output; RMAC mismatch and RT-4/RT-1 inconsistency diagnostics are not asserted. |

### ES-to-VRF association and IP A-D

| ID | Requirement or functionality | Automated evidence | Status | Residual risk |
|---|---|---|---|---|
| EAD-01 | Protected L3MH ESes create L3VNI ES-EVI associations; ordinary L2VNI ES-EVIs remain unchanged. | `test_bpp_es_vrf_assoc`, `test_bpp_es_evi_l2vni_unchanged`, `test_bpp_l2_untouched` | **Covered** | None identified in FRR. |
| EAD-02 | L3VNI ES-EVIs survive and are replayed after bgpd restart. | `test_bpp_es_evi_bgpd_restart` | **Covered** | This is bgpd restart, not zebra restart. |
| EAD-03 | An unknown VNI is rejected when `l3vni-neigh` is off; with L3MH enabled, an early ES-EVI remains pending until its L3VNI appears. | `test_bpp_es_evi_unknown_vni_rejected`, `test_bpp_es_evi_l3vni_order` | **Covered** | Allocator/resource exhaustion is not injected. |
| EAD-04 | IP A-D per-EVI is originated per protected IP-VRF with its L3VNI label and Router's MAC EC. | `test_bpp_ip_ead_tx`, `test_bpp_ip_ead_tx_rmac_change` | **Covered** | Exact on-wire BGP packet bytes are not decoded by the test. |
| EAD-05 | IP A-D per-ES follows ES state, uses the configured route targets, and supports fragmentation. | `test_bpp_ip_ead_tx`, `test_bpp_ip_ead_tx_per_es_frag`, `test_bpp_ip_ead_tx_rt_change`, `test_bpp_ip_ead_tx_local_es_down` | **Covered** | Maximum fragmentation scale is not tested. |
| EAD-06 | IP A-D next hops use the configured VXLAN endpoint, including IPv6, rather than another global address. | `test_bpp_ip_ead_tx_ipv6` with a competing management IPv6 address | **Covered** | FPM wire encoding is external. |
| EAD-07 | Per-EVI origination follows ready VLAN/IP-VRF configuration while per-ES origination follows ES operational state. | `test_bpp_ip_ead_tx_withdraw` | **Covered** | None identified in FRR. |
| EAD-08 | Received per-EVI and per-ES routes are classified and scoped to the correct ESI and IP-VRF. | `test_bpp_ip_ead_rx_classify`, `test_bpp_ip_ead_rx_mac_scope_only`, `test_bpp_other_esi` | **Partial** | A route imported into both MAC-VRF and IP-VRF scopes is not tested independently in both scopes, and the RX helper can tolerate extra stale VTEPs. |
| EAD-09 | A per-EVI label/L3VNI mismatch is ignored. | `test_bpp_ip_ead_rx_label_mismatch` | **Covered** | None identified in FRR. |
| EAD-10 | A per-EVI route without Router's MAC EC is ineligible. | `test_bpp_ip_ead_rx_no_rmac_ec`, `test_bpp_ineligible_rx` | **Covered** | No fallback to RT-2/RT-5 is intended. |
| EAD-11 | RX classification is gated by `l3vni-neigh`, but is independent of local protection and is retained for remote-only ESes; only local eligibility/export is protection-gated. | `test_bpp_ip_ead_rx_knob_off`, `test_bpp_ip_ead_rx_protection_off`, `test_bpp_ip_ead_rx_remote_only_es` | **Covered** | The receive helper can tolerate unexpected stale VTEPs when the flagged subset matches. |
| EAD-12 | Existing L3MH neighbor synchronization coexists with IP A-D processing. | `test_bpp_neigh_sync_coexist`; full `bgp_evpn_l3mh` regression | **Partial** | The focused test accepts any ToR with one `extern_learn` neighbor instead of verifying the complete expected synchronization set. Full FRR CI remains pending. |
| EAD-13 | A received per-EVI route is usable for this all-active design only when the Layer-2 Attributes EC has `P=1`. | TX tests confirm local `P=1` origination; no negative RX test exists. | **Pending** | No `P=0`/single-active route rejection test was found, and RX implementation does not visibly check this field. |
| EAD-14 | Attribute-only updates replace a path's IP A-D import ownership instead of adding references; its withdrawal removes all state. | `test_bpp_ip_ead_rx_attr_update_withdraw` | **Covered** | None identified in FRR. |

### Eligibility, RMAC, and ZAPI

| ID | Requirement or functionality | Automated evidence | Status | Residual risk |
|---|---|---|---|---|
| ELIG-01 | A peer is eligible only with matching per-EVI and per-ES IP A-D coverage in every ready IP-VRF of the ES. | `test_bpp_eligibility`, `test_bpp_eligibility_all_vrfs`, `test_bpp_group_all_vrfs`, `test_bpp_vrf_no_per_evi` | **Covered** | None identified in tested VRF counts. |
| ELIG-02 | A new local ready VRF immediately invalidates a peer until that peer covers the new VRF. | `test_bpp_new_local_vrf` | **Covered** | None identified in FRR. |
| ELIG-03 | One resolver emits exactly one peer transition, not one transition per VRF. | `test_bpp_single_resolver`, `test_bpp_fanout` | **Covered** | None identified in FRR. |
| ELIG-04 | RT-4 is diagnostic only: absence, late arrival, or withdrawal does not gate an otherwise eligible peer; RT-4 alone is insufficient. | `test_bpp_rt4_initial_admission`, `test_bpp_rt4_late_arrival`, `test_bpp_rt4_withdraw`, `test_bpp_rt4_only` | **Covered** | None identified in FRR. |
| ELIG-05 | Host RT-2/RT-5 activity does not generate protection-peer transitions. | `test_bpp_host_route_no_effect` | **Partial** | The test generates host traffic but does not prove that both RT-2 and RT-5 add/withdraw transitions occurred while BPP state remained unchanged. |
| ELIG-06 | Different ESI, non-L3MH ES, remote-only ES, and unprotected ES state cannot generate a peer. | `test_bpp_other_esi`, `test_bpp_non_l3mh_es`, `test_bpp_remote_only_es_no_send`, `test_bpp_unprotected_l3mh_es` | **Covered** | None identified in FRR. |
| ELIG-07 | Removing `l3vni-neigh`, protection, required remote per-EVI coverage, or peer reachability sends a DEL; restoration sends ADD. Removing a local VRF from the required set can make a peer eligible. | `test_bpp_knob_off_del`, `test_bpp_protection_off_del`, `test_bpp_per_evi_one_vrf`, `test_bpp_peer_vtep_unreachable`, `test_bpp_vrf_leaves_ready_set` | **Covered** | None identified in FRR. |
| RMAC-01 | Member RMAC comes from the per-EVI Router's MAC EC and is common to the peer VTEP. | `test_bpp_rmac_common_multi_vrf`, `test_bpp_member_rmac` | **Covered** | RT-2/RT-5 independence is inferred through route filtering/activity, not packet-level timing injection. |
| RMAC-02 | If VRFs advertise different RMACs for one VTEP, the latest received RMAC wins. | `test_bpp_rmac_latest` | **Covered** | Per-VRF RMAC identities are deliberately unsupported. |
| RMAC-03 | RMAC change sends ADD with the new RMAC and no DEL; the Member and Group IDs stay stable. | `test_bpp_rmac_change`, `test_bpp_ids_stable`, `test_bpp_rmac_change_export` | **Covered** | Actual FPM bytes and SONiC replacement are external. |
| ZAPI-01 | L3VNI ES-EVI and BPP peer messages carry the required ESI, type, VTEP family/address, and RMAC semantics. | `test_bpp_zapi`, IPv4/IPv6 eligibility tests | **Partial** | Tests observe successful zebra receipt/state but not exact length, DEL key-only form, trailing data, invalid family/type, zero RMAC, or short/malformed-message rejection. |
| ZAPI-02 | Existing L2 remote-ES processing and kernel L2 nexthops are unchanged. | `test_bpp_l2_untouched`, `test_bpp_l2_br_port_unchanged` | **Partial** | The bridge-port test does not snapshot an actual L2 bridge-port update; full EVPN CI remains pending. |

### Groups, Members, Bindings, and identifiers

| ID | Requirement or functionality | Automated evidence | Status | Residual risk |
|---|---|---|---|---|
| OBJ-01 | One Group exists per protected ESI, even when two ESes have the same peer set. | `test_bpp_group_per_es_same_peers`, `test_bpp_scale` | **Covered** | None identified in FRR. |
| OBJ-02 | One Member identity exists per `(type, family, VTEP)` and is shared across Groups. | `test_bpp_member_shared`, `test_bpp_dual_family_same_peer` | **Covered** | SONiC identity mapping is external. |
| OBJ-03 | A Group carries its ESI and complete Member records sorted by `nh_id`. | ESI and membership are exercised by `test_bpp_dplane_emit`, `test_bpp_show_member`, and `test_bpp_replay`. | **Pending** | Tests compare sets/sorted copies, not payload order or every full Member field. The implementation currently sorts peers by type/VTEP rather than `nh_id`, contrary to the frozen FPM contract. |
| OBJ-04 | One Binding associates the ES bond with its Group and covers all protected VLANs. | `test_bpp_dplane_emit`, `test_bpp_fanout`, `test_bpp_l2vni_on_bd_binding`, `test_bpp_scale` | **Covered** | The all-VLAN scope is inferred from the single bond Binding because the Binding has no VLAN list. ASIC bridge-port programming is external. |
| OBJ-05 | IPv4 and IPv6 Members are distinct and include family, VTEP, type, and RMAC. | `test_bpp_ipv6_vtep`, `test_bpp_dual_family_same_peer`, `test_bpp_member_rmac`, `test_bpp_show_member` | **Covered** | Exact FPM IPv6 serialization is external. |
| OBJ-06 | A protection Binding carries the bond ifindex, type-8 backup Group, `non_df=false`, and an empty split-horizon list. | Bond/interface and Group ID are visible in `test_bpp_dplane_emit`. | **Partial** | No test directly inspects the dplane context for `non_df=false` and an empty split-horizon list. |
| ID-01 | Member IDs have type 4, Group IDs have type 8, and both use the FPM channel only. | `test_bpp_id_disjoint`, `test_bpp_fpm_kernel_disjoint` | **Covered** | The external FPM consumer must use the same tags. |
| ID-02 | L3 protection IDs cannot alias L2 NH/NHG IDs or kernel nexthop IDs, including for the same VTEP and after churn. | `test_bpp_id_disjoint`, `test_bpp_id_disjoint_same_vtep`, `test_bpp_id_disjoint_churn`, `test_bpp_group_separate_from_l2_nhg`, `test_bpp_fpm_kernel_disjoint` | **Covered** | Mixed-version SONiC is outside FRR. |
| ID-03 | IDs remain stable for unchanged objects, Group updates, and RMAC updates while zebra is alive. | `test_bpp_ids_stable`, `test_bpp_peer_join_leave`, `test_bpp_rmac_change_export`, `test_bpp_replay` | **Covered** | IDs intentionally change after zebra restart. |
| ID-04 | Retired IDs are not reused during the zebra lifetime or while deletes are pending. | `test_bpp_id_no_reuse`; `bpp_export_check()` pending-delete checks | **Covered** | Allocator exhaustion under sustained lifetime churn is not stress-tested. |
| ID-05 | Kernel enqueue rejects type-4/type-8 IDs and protection enqueue rejects type-1/type-2 IDs. | Disjoint-state tests prove normal-path separation. | **Partial** | No negative guard-injection test directly exercises either rejection path. |

### Export lifecycle, replay, restart, and scale

| ID | Requirement or functionality | Automated evidence | Status | Residual risk |
|---|---|---|---|---|
| LIFE-01 | Initial state exports Members, a Group, and one Binding; no protection ID is sent to kernel. Member-before-Group-before-Binding create order is best-effort, not a correctness requirement. | `test_bpp_dplane_emit`, `test_bpp_fpm_kernel_disjoint`; retained-log consistency checks | **Partial** | Object presence and references are covered, but a self-contained Group's exact complete Member records are not validated. This does not test FPM wire bytes. |
| LIFE-02 | Peer join adds the Member before replacing the existing Group; no Binding resend occurs. | `test_bpp_peer_join_leave`, `test_bpp_scale`; `bpp_export_check()` | **Covered** | Out-of-order consumer parking is external. |
| LIFE-03 | Peer leave replaces the Group before deleting an unreferenced Member; the Binding remains while the Group is non-empty. | `test_bpp_peer_join_leave`, `test_bpp_per_evi_one_vrf`, `test_bpp_per_es_mass_withdraw` | **Covered** | SONiC application is external. |
| LIFE-04 | Last peer, feature disable, or ES deletion deletes Binding, Group, then unreferenced Members. | `test_bpp_last_peer`, `test_bpp_disable`, `test_bpp_es_delete`, `test_bpp_per_es_mass_withdraw` | **Covered** | SONiC application is external. |
| LIFE-05 | RMAC update replaces Member and Group in place without Binding resend or Member delete. | `test_bpp_rmac_change_export` | **Covered** | SONiC replace semantics are external. |
| LIFE-06 | Local link down/up emits no protection update and changes no primary forwarding state. | `test_bpp_local_link_down` | **Covered** | Actual ASIC failover and traffic continuity are external. |
| LIFE-07 | Per-EVI loss in one VRF and per-ES mass withdrawal converge with correct object retention/deletion. | `test_bpp_per_evi_one_vrf`, `test_bpp_per_es_mass_withdraw` | **Covered** | None identified in FRR. |
| REPLAY-01 | Replay emits all Members, Groups, and Bindings with unchanged IDs and ends with exactly one `REPLAY_DONE`. | `test_bpp_replay` | **Covered** | Invoked through the Tier-1 replay command, not an actual FPM reconnect. |
| REPLAY-02 | Empty replay emits exactly one `REPLAY_DONE`. | `test_bpp_replay_empty` | **Covered** | Actual FPM session establishment is external. |
| REPLAY-03 | Replay is idempotent and does not change primary MAC, neighbor, route, ES, FDB, or dplane counters. | `test_bpp_replay`, `test_bpp_replay_idempotent` | **Covered** | Full forwarding state is checked after one replay; repeated replay checks export-table stability. SONiC duplicate-message handling is external. |
| RESTART-01 | `frr-reload.py` causes no unnecessary export; zebra restart rebuilds objects with the same ESI and new Group IDs. | `test_bpp_config_reload` | **Covered** | Reload absence is checked immediately rather than through a settling window. SONiC mapping old/new IDs and stale-object sweep are not exercised. |
| SCALE-01 | At least 8 protected ESes, 32 VLANs, 4 L3VNIs, and 3 peers per Group converge. | `test_bpp_scale` | **Covered** | This is the minimum design scale, not a product maximum. |
| SCALE-02 | Peer churn at that scale changes Group membership without Binding resend. | `test_bpp_scale` | **Covered** | No sustained churn or performance/latency benchmark is captured. |
| SCALE-03 | Protection state scales with ES/VLAN/VTEP identities rather than host MAC/route count. | Object-count assertions in `test_bpp_scale` | **Partial** | Host/route cardinality is not independently increased to prove invariance. |
| ERR-01 | Dplane/FPM failure is reported while desired state is preserved and retried safely. | No failure-injection test. | **Pending** | Failed ADD/DEL, retry, delete-ack failure, and last-error visibility are not demonstrated. |
| ERR-02 | Invalid peer VTEPs, FPM serialization failures, and unsupported forwarding-object capability are rejected and reported without partial state. | No negative test. | **Pending** | HLD Section 12 error paths are not demonstrated. |

## Phase 13 consolidated checklist

| # | Required scenario | Evidence | Status |
|---|---|---|---|
| 1 | Steady state: one Group per ES, Members, one Binding per ES bond | `test_bpp_dplane_emit`, `test_bpp_scale` | **Covered** |
| 2 | Peer join: in-place Group update | `test_bpp_peer_join_leave` | **Covered** |
| 3 | Peer per-ES withdrawal removes it from the Group | `test_bpp_per_es_mass_withdraw` | **Covered** |
| 4 | Peer per-EVI withdrawal in one VRF removes it from the Group | `test_bpp_per_evi_one_vrf` | **Covered** |
| 5 | No peer covers every VRF: Group empty and bond unbound | `test_bpp_group_all_vrfs`, `test_bpp_vrf_no_per_evi` | **Covered** |
| 6 | Last peer gone: complete withdrawal | `test_bpp_last_peer` | **Covered** |
| 7 | RT-4 never changes eligibility | Four `test_bpp_rt4_*` tests | **Covered** |
| 8 | L3MH gate and L2VNI-on-BD behavior | `test_bpp_l3mh_gate`, `test_bpp_l3mh_bd_gets_l2vni`, `test_bpp_l2vni_on_bd_binding` | **Covered** |
| 9 | IP A-D TX follows config/ES state and local Bindings remain installed across link state | TX/withdrawal tests and `test_bpp_local_link_down` | **Covered** |
| 10 | IP A-D RX scope, label mismatch, and missing RMAC EC | RX classify/negative tests | **Partial** — core classification and negative cases are covered; dual MAC-VRF/IP-VRF scope and strict extra-state rejection are not |
| 11 | L3MH neighbor sync remains green | `test_bpp_neigh_sync_coexist`; 58-test L3MH regression | **Covered** |
| 12 | Latest RMAC and RMAC change | RMAC tests in bgpd and export lifecycle | **Covered** |
| 13 | Unprotected L3MH ES exports nothing until enabled | `test_bpp_unprotected_l3mh_es` | **Covered** |
| 14 | IPv4 and IPv6 VTEPs | IPv6 and dual-family tests | **Covered** |
| 15 | L2 ES behavior remains unchanged | L2 untouched, bridge-port, and ID-disjoint tests | **Partial** — normal L2 state is checked, but an actual L2 bridge-port update is not snapshotted and full EVPN CI is pending |
| 16 | Local link down changes nothing | `test_bpp_local_link_down` | **Covered** |
| 17 | Replay keeps IDs, ends in marker, and preserves primary path | Replay tests | **Covered** for Tier 1; actual FPM reconnect is **External** |
| 18 | Zebra restart rebuilds clean state | `test_bpp_config_reload` | **Covered** in FRR; SONiC reconciliation is **External** |
| 19 | Binding-first delivery converges | No Tier-2 SONiC stand-in is present in this branch | **External/Pending** |
| 20 | IDs are kernel-disjoint and not reused before delete completion or later in the zebra lifetime | ID and FPM/kernel disjoint tests; checker | **Covered** |
| 21 | Scale minimum and churn without Binding resend | `test_bpp_scale` | **Covered** |

## Automated test inventory

Every test in `test_bgp_evpn_mh_bpp.py` is accounted for below.

### Topology prerequisites

- `test_bgp_sessions`
- `test_l3vnis_up`
- `test_es_on_all_tors`

### Configuration, entries, show, and debug

- `test_bpp_config`
- `test_bpp_entries`
- `test_bpp_pending_reasons`
- `test_bpp_link_state`
- `test_bpp_show`
- `test_bpp_debug`

### ES-to-IP-VRF association

- `test_bpp_es_vrf_assoc`
- `test_bpp_l3mh_gate`
- `test_bpp_l3mh_bd_gets_l2vni`
- `test_bpp_es_evi_l2vni_unchanged`
- `test_bpp_es_evi_bgpd_restart`
- `test_bpp_es_evi_pending_es`
- `test_bpp_es_evi_l3vni_order`
- `test_bpp_es_evi_unknown_vni_rejected`

### IP A-D origination

- `test_bpp_ip_ead_tx`
- `test_bpp_ip_ead_tx_ipv6`
- `test_bpp_ip_ead_tx_per_es_frag`
- `test_bpp_ip_ead_tx_no_l3mh`
- `test_bpp_ip_ead_tx_withdraw`
- `test_bpp_ip_ead_tx_svi_oper`
- `test_bpp_ip_ead_tx_local_es_down`
- `test_bpp_ip_ead_tx_rt_change`
- `test_bpp_ip_ead_tx_rmac_change`

### IP A-D receive and L3MH coexistence

- `test_bpp_ip_ead_rx_classify`
- `test_bpp_ip_ead_rx_attr_update_withdraw`
- `test_bpp_ip_ead_rx_mac_scope_only`
- `test_bpp_ip_ead_rx_label_mismatch`
- `test_bpp_ip_ead_rx_no_rmac_ec`
- `test_bpp_ip_ead_rx_knob_off`
- `test_bpp_ip_ead_rx_protection_off`
- `test_bpp_ip_ead_rx_remote_only_es`
- `test_bpp_neigh_sync_coexist`

### ZAPI, eligibility, and RMAC resolution

- `test_bpp_zapi`
- `test_bpp_l2_untouched`
- `test_bpp_eligibility`
- `test_bpp_eligibility_all_vrfs`
- `test_bpp_new_local_vrf`
- `test_bpp_single_resolver`
- `test_bpp_rmac_common_multi_vrf`
- `test_bpp_rmac_latest`
- `test_bpp_rmac_change`
- `test_bpp_eligibility_order`
- `test_bpp_rt4_initial_admission`
- `test_bpp_rt4_late_arrival`
- `test_bpp_rt4_withdraw`
- `test_bpp_rt4_only`
- `test_bpp_host_route_no_effect`
- `test_bpp_other_esi`
- `test_bpp_non_l3mh_es`
- `test_bpp_ineligible_rx`
- `test_bpp_knob_off_del`
- `test_bpp_protection_off_del`
- `test_bpp_remote_only_es_no_send`
- `test_bpp_vrf_leaves_ready_set`
- `test_bpp_fanout`
- `test_bpp_pending_vlan`

### Group, Member, Binding, and ID model

- `test_bpp_show_member`
- `test_bpp_group_all_vrfs`
- `test_bpp_vrf_no_per_evi`
- `test_bpp_unprotected_l3mh_es`
- `test_bpp_member_rmac`
- `test_bpp_ipv6_vtep`
- `test_bpp_dual_family_same_peer`
- `test_bpp_id_disjoint`
- `test_bpp_id_disjoint_same_vtep`
- `test_bpp_member_shared`
- `test_bpp_group_per_es_same_peers`
- `test_bpp_id_disjoint_churn`
- `test_bpp_group_separate_from_l2_nhg`
- `test_bpp_ids_stable`
- `test_bpp_id_no_reuse`

### Export lifecycle, replay, restart, and scale

- `test_bpp_dplane_emit`
- `test_bpp_peer_join_leave`
- `test_bpp_last_peer`
- `test_bpp_disable`
- `test_bpp_es_delete`
- `test_bpp_per_evi_one_vrf`
- `test_bpp_per_es_mass_withdraw`
- `test_bpp_peer_vtep_unreachable`
- `test_bpp_rmac_change_export`
- `test_bpp_local_link_down`
- `test_bpp_replay`
- `test_bpp_replay_empty`
- `test_bpp_replay_idempotent`
- `test_bpp_config_reload`
- `test_bpp_scale`
- `test_bpp_fpm_kernel_disjoint`
- `test_bpp_l2_br_port_unchanged`
- `test_bpp_l2vni_on_bd_binding`
- `test_bpp_export_status`

### Optional memory validation

- `test_memory_leak` — skipped unless FRR memory-leak reporting is enabled.

## Gaps and required follow-up

The audit does **not** support a claim of complete end-to-end coverage yet.
The following items remain:

| Priority | Gap | Why it matters | Required closure |
|---|---|---|---|
| P0 | Group Members are sorted by type/VTEP, not by `nh_id` as required by the frozen FPM contract; no test checks payload order. | Different ordering can cause unnecessary replacements and violates the deterministic complete-object contract. | Sort the exported Group array by `nh_id` and add an exact-order assertion. |
| P0 | No negative RX test or visible eligibility check enforces all-active `P=1` on per-EVI IP A-D. | A single-active (`P=0`) route could become a protection Member even though only all-active L3MH is supported. | Add explicit `P=0` rejection in bgpd and a negative topotest. |
| P0 | No actual `dplane_fpm_sonic` wire encoder/decoder test or SONiC stand-in is present in this FRR branch. | FRR dplane contexts can be correct while message numbers, native ABI sizes/offsets, family encoding, ESI, count, or variable Group length are wrong on the wire. | Add/run golden byte-vector tests for Member, Group, Binding, and `REPLAY_DONE`, for ADD/DEL, IPv4/IPv6, and RMAC update. |
| P0 | No SONiC/ASIC end-to-end failover test is part of this suite. | FRR export correctness does not prove bridge-port protection programming, failover, or traffic continuity. | Run the SONiC VS/system tests for APPL_DB/ASIC_DB object lifecycle and traffic failover/recovery. |
| P1 | Dplane/FPM error handling is not injected or demonstrated. | The HLD requires error reporting, desired-state preservation, and safe retry; delete failures also interact with ID retirement. Invalid peer VTEP, serialization failure, and unsupported-object capability mismatch paths are untested. | Inject failed ADD/DEL completions and serialization, invalid VTEPs, and capability mismatch; verify rejection, state, last-error visibility, retry, and ID retention. |
| P1 | Strict ZAPI rejection is not tested. | Short/trailing payloads, invalid family/type, zero RMAC, or a malformed DEL could partially corrupt state. | Add encode/decode unit tests for exact ADD/DEL payloads and all malformed forms. |
| P1 | FPM reconnect is represented by the Tier-1 replay command, not a real provider session reconnect. | Session-start callbacks, ordering, and marker delivery could differ from direct invocation. | Add a Tier-2 test that disconnects/reconnects the real or stand-in FPM consumer. |
| P1 | Binding-first/out-of-order consumer convergence is not exercised. | Create order is best-effort and SONiC is required to park unresolved references. | Add the planned SONiC stand-in test that deliberately reorders/parks Binding, Group, and Member messages. |
| P1 | Zebra restart is validated only from FRR's rebuilt export tables. | The contract requires SONiC to map new IDs by ESI/Member identity and sweep stale objects only after `REPLAY_DONE`. | Add a stateful consumer test across zebra restart, including an object removed while zebra is down. |
| P1 | Pending and diagnostics coverage is incomplete. | Missing SVI/IP-VRF, L3VNI-down, simultaneous reasons, RMAC mismatch, RT-4/RT-1 inconsistency, and last FPM error may be invisible or incorrect. | Add exact state/reason tests with event-scoped log matching and failure injection. |
| P1 | A route matching both MAC-VRF and IP-VRF RTs is not tested in both scopes. | One scope could suppress or consume processing required by the other. | Add a dual-import-scope RT-1 test and assert independent MAC-VRF and IP-VRF state. |
| P1 | Changed-line coverage above 80% has not been measured. | It is an explicit Phase 13 exit criterion. | Run CI coverage and attach the changed-line report; add tests for uncovered error paths. |
| P1 | Full FRR CI and all existing EVPN regressions have not been recorded. | Local BPP and L3MH results do not prove repository-wide compatibility. | Run the branch through FRR CI and record all EVPN results. |
| P2 | Memory-leak validation was skipped. | Bulk IP A-D churn previously exposed a lifetime bug. | Rerun the BPP suite with memory-leak reporting and preferably ASAN enabled. |
| P2 | Member limits are inconsistent and untested: BPP currently uses `ES_VTEP_MAX_CNT=10`, dplane declares 510, and the frozen contract states 4096. | Silent truncation can produce an incomplete protection Group well below the contract maximum. | Reconcile the supported limit across design and code, reject overflow explicitly, and add boundary tests. |
| P2 | Cross-table validation is incomplete. | The checker does not fully prove every Group table Member exists in the Member table or that Binding/Group ESI and interface ownership agree. | Strengthen `bpp_export_check()` and add negative unit fixtures for each inconsistency. |
| P2 | Several focused assertions are permissive or indirect. | Extra stale RX VTEPs, conflicting per-VRF eligibility, inactive VLAN export status, stale log matches, and delayed reload exports could escape detection. | Tighten helpers to reject extras, isolate events, require expected ACTIVE VLANs, and use convergence windows. |
| P2 | State proportionality is inferred, not stress-proven against host/route cardinality. | The HLD states that state must not scale with hosts, MACs, or routes behind the ES. | Add many host MAC/route entries while holding ES/VLAN/VTEP counts fixed and assert protection object counts remain fixed. |
| P2 | FPM capability/version negotiation is absent. | Mixed FRR/SONiC versions can disagree on private message ABI. | Resolve the explicitly deferred negotiation design before mixed-version deployment. |

## Explicitly deferred or out-of-scope

These are not missing initial-release tests:

| Item | Disposition |
|---|---|
| L2 protection Members | Wire field reserved; behavior deferred. |
| Single-active multihoming | Forwarding behavior is out of scope; rejecting a `P=0` peer remains an in-scope all-active admission requirement and is listed as a P0 gap. |
| L2VNI and L3VNI on the same protected ES | Deferred; current behavior remains pending when an L2VNI is present. |
| VLAN subinterfaces as bridge ports | Deferred; the ES bond is the bridge port. |
| Different simultaneous RMAC identities per VRF for one VTEP | Deferred; latest RMAC wins globally for that VTEP. |
| Warm reboot | Out of FRR scope; SONiC owns persistent identity and reconciliation. |
| Router's MAC fallback from RT-2/RT-5 | Not planned; missing Router's MAC EC on per-EVI is ineligible. |

## Exit criteria

FRR control-plane implementation can be considered locally complete when:

- all rows marked **Covered** continue to pass;
- changed-line coverage exceeds 80%;
- the memory-leak/ASAN run passes;
- full FRR CI, including existing EVPN suites, is green.

The overall feature can be considered end-to-end complete only after the P0
and P1 SONiC/FPM gaps above are closed.
