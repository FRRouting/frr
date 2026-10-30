# SPDX-License-Identifier: ISC
#
# Consistency checks for "show evpn mh bridge-port-protection export json".
# Copyright (c) 2026 Cisco Systems, Inc.
# Patrice Brissette
#

NHG_TYPE_L3_BPP_NH = 4
NHG_TYPE_L3_BPP = 8


def _nhg_type(nhid):
    return (int(nhid) >> 28) & 0xF


def bpp_export_check(export):
    """Return a list of consistency errors; empty means the export is clean."""
    errors = []
    log = export.get("log") or []
    tables = export.get("tables") or {}
    live_members = set()
    live_groups = {}
    live_bindings = {}
    inflight_del = set()
    bind_on_wire = set()

    for ent in log:
        op = ent.get("op")
        action = ent.get("action")
        oid = int(ent.get("id") or 0)
        ifname = ent.get("interface")

        if action != "del" and oid in inflight_del:
            errors.append("id 0x%x reused before delete completed seq %s" % (oid, ent.get("seq")))

        if op == "EVPN_MH_NH_UPDATE":
            if action == "del":
                for gid, mids in live_groups.items():
                    if oid in mids:
                        errors.append(
                            "Member 0x%x deleted while Group 0x%x seq %s"
                            % (oid, gid, ent.get("seq"))
                        )
                live_members.discard(oid)
                inflight_del.add(oid)
            else:
                live_members.add(oid)
        elif op == "EVPN_MH_NHG_UPDATE":
            mids = [int(x) for x in (ent.get("memberIds") or [])]
            if action == "del":
                for ifn, gid in live_bindings.items():
                    if gid == oid:
                        errors.append(
                            "Group 0x%x deleted while Binding %s seq %s"
                            % (oid, ifn, ent.get("seq"))
                        )
                live_groups.pop(oid, None)
                inflight_del.add(oid)
            else:
                if not mids:
                    errors.append("empty Group 0x%x seq %s" % (oid, ent.get("seq")))
                for mid in mids:
                    if mid not in live_members:
                        errors.append(
                            "Group 0x%x missing Member 0x%x seq %s" % (oid, mid, ent.get("seq"))
                        )
                live_groups[oid] = mids
        elif op == "BR_PORT_UPDATE":
            if action == "del":
                live_bindings.pop(ifname, None)
                bind_on_wire.discard(ifname)
            else:
                if ifname in bind_on_wire:
                    errors.append("Binding resent on %s seq %s" % (ifname, ent.get("seq")))
                if oid and oid not in live_groups:
                    errors.append(
                        "Binding %s to missing Group 0x%x seq %s" % (ifname, oid, ent.get("seq"))
                    )
                live_bindings[ifname] = oid
                bind_on_wire.add(ifname)

        if action == "del" and ent.get("completed"):
            inflight_del.discard(oid)

    for rec in (tables.get("members") or {}).values():
        nhid = int(rec.get("nhId") or 0)
        if _nhg_type(nhid) != NHG_TYPE_L3_BPP_NH:
            errors.append("Member 0x%x has type %s" % (nhid, _nhg_type(nhid)))
    for rec in (tables.get("groups") or {}).values():
        gid = int(rec.get("nhgId") or 0)
        if _nhg_type(gid) != NHG_TYPE_L3_BPP:
            errors.append("Group 0x%x has type %s" % (gid, _nhg_type(gid)))
        if not rec.get("members"):
            errors.append("Group 0x%x has no members in tables" % gid)
        if not rec.get("esi"):
            errors.append("Group 0x%x has no ESI" % gid)
    for rec in (tables.get("bindings") or {}).values():
        gid = int(rec.get("backupNhgId") or 0)
        if gid and _nhg_type(gid) != NHG_TYPE_L3_BPP:
            errors.append("Binding %s backup 0x%x type %s" % (rec.get("interface"), gid, _nhg_type(gid)))

    return errors
