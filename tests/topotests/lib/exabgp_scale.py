# SPDX-License-Identifier: ISC
#
# Many BGP sessions from one ExaBGP peer.
#
# Existing ExaBGP topotests add one TopoExaBGP gear per session, each with
# its own static peerN/exabgp.cfg, and start it with:
#
#     peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))
#
# A test that needs hundreds of sessions keeps that gear and that start().
# This module only builds the configuration and the extra addresses.
# Typical use, after tgen.start_topology():
#
#     peer = tgen.gears["peer1"]
#     config = "".join(
#         exabgp_scale.neighbor_block(
#             peer_address=remote, local_address=local,
#             local_as=local_as, peer_as=remote_as,
#         )
#         for local, remote in sessions
#     )
#     exabgp_scale.add_addresses(peer, "peer1-eth0", sources)
#     peer.start(
#         exabgp_scale.write_peer_dir(peer, config),
#         os.path.join(CWD, "exabgp.env"),
#     )
#
# stop_topology() still stops the process through TopoExaBGP.stop().

import os


def neighbor_block(peer_address, local_address, local_as, peer_as, families=None):
    """Return one ExaBGP neighbor stanza.

    peer_address is the address ExaBGP connects to. local_address is used
    as both router-id and local-address, so the session binds that source.
    local_as is the ExaBGP AS and peer_as is the DUT AS. families is a list
    of "afi safi" strings and defaults to ["ipv4 unicast"].

    ExaBGP rejects a block whose peer address, local address, local AS,
    peer AS, and router-id are all identical to an earlier block
    ("duplicate peer definition"). The peer address may be repeated when
    the local address differs, and the local address may be repeated when
    the peer address differs. This function sets router-id from
    local_address, so two blocks that share both addresses are rejected.
    The text matches the static peerN/exabgp.cfg files. Concatenate the
    results to build the config passed to write_peer_dir().
    """
    if families is None:
        families = ["ipv4 unicast"]
    lines = [
        "neighbor {} {{".format(peer_address),
        "  router-id {};".format(local_address),
        "  local-address {};".format(local_address),
        "  local-as {};".format(local_as),
        "  peer-as {};".format(peer_as),
        "  family {",
    ]
    lines.extend("    {};".format(family) for family in families)
    lines.extend(["  }", "}", ""])
    return "\n".join(lines)


def write_peer_dir(peer, config):
    """Write config to <logdir>/<peer>-exabgp/exabgp.cfg and return that directory.

    peer is the TopoExaBGP gear. config is the full configuration text,
    normally the concatenation of neighbor_block() results. Pass the
    returned directory as the peer_dir argument of TopoExaBGP.start();
    start() copies it into the gear's private /etc/exabgp. Call this
    after the topology is up and before peer.start().
    """
    peer_dir = os.path.join(peer.logdir, "{}-exabgp".format(peer.name))
    os.makedirs(peer_dir, exist_ok=True)
    with open(os.path.join(peer_dir, "exabgp.cfg"), "w", encoding="ascii") as handle:
        handle.write(config)
    return peer_dir


def add_addresses(peer, ifname, addresses, prefixlen=32):
    """Install addresses on ifname inside the ExaBGP gear.

    add_exabgp_peer() configures one address on the gear. ExaBGP fails to
    bind a local-address that is not configured, so every local_address
    passed to neighbor_block() must be in addresses. ifname is the gear
    interface, "<name>-eth0" for its first link. prefixlen defaults to 32.

    The addresses are applied with one "ip -force -batch", which raises if
    any of them cannot be added. Call this after start_topology() and
    before peer.start().
    """
    path = os.path.join(peer.logdir, "{}-addresses.batch".format(peer.name))
    with open(path, "w", encoding="ascii") as handle:
        for address in addresses:
            handle.write(
                "address add {}/{} dev {}\n".format(address, prefixlen, ifname)
            )
    peer.cmd_raises("ip -force -batch {}".format(path))


def log_tail(peer, lines=40):
    """Return the last lines of the ExaBGP log, or a message if it cannot be read.

    TopoExaBGP.start() sends the log to <logdir>/<peer>/exabgp.log. lines
    is how many trailing lines to keep and defaults to 40. Use this when a
    session fails to come up.
    """
    path = os.path.join(peer.logdir, peer.name, "exabgp.log")
    try:
        with open(path, encoding="ascii", errors="replace") as handle:
            data = handle.readlines()
    except OSError as err:
        return "exabgp log {}: {}".format(path, err)
    return "".join(data[-lines:])
