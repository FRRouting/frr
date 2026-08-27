#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

#
# mock_pce.py
#

"""
Minimal scripted PCE for the pathd PCEP steering topotest.

Implements just enough of RFC 5440 (PCEP), RFC 8231 (stateful),
RFC 8281 (PCE-initiated) and RFC 8664 (SR ERO) to drive FRR's pathd
as a PCC:

1. Accept the PCC's TCP connection and exchange Open/Keepalive.
2. Wait for the PCC's end-of-state-sync PCRpt (an LSP object with
   PLSP-ID 0 and the SYNC flag clear).  pathd silently discards any
   PCInitiate received before that point.
3. Send a single PCInitiate creating one SR policy (SRP + LSP with
   symbolic name + IPv4 END-POINTS + ERO with one SID-only SR
   subobject).
4. Keep the session alive with periodic Keepalives.

State transitions are appended to a log file.
"""

import argparse
import os
import select
import socket
import struct
import threading
import time

PCEP_VERSION_BYTE = 0x20  # version 1, flags 0

MSG_OPEN = 1
MSG_KEEPALIVE = 2
MSG_ERROR = 6
MSG_REPORT = 10
MSG_INITIATE = 12

CLASS_OPEN = 1
CLASS_ENDPOINTS = 4
CLASS_ERO = 7
CLASS_ERROR = 13
CLASS_LSP = 32
CLASS_SRP = 33
CLASS_VENDOR_INFO = 34

# FRR reads the policy color from a VENDOR-INFO object carrying this
# enterprise number and enterprise-specific info value.
VENDOR_ENTERPRISE_CISCO = 9
VENDOR_ESI_COLOR = 0x00010004

TLV_STATEFUL_CAP = 16
TLV_SYMBOLIC_NAME = 17
TLV_SR_CAP = 26
TLV_PATH_SETUP_TYPE = 28
TLV_PST_CAP = 34

LSP_FLAG_SYNC = 0x02


def parse_policy(spec):
    """Parse an endpoint,label,name[,color] --policy argument."""
    fields = spec.split(",")
    if len(fields) not in (3, 4):
        raise argparse.ArgumentTypeError(
            "--policy takes endpoint,label,name[,color]: %s" % spec
        )
    return {
        "endpoint": fields[0],
        "label": int(fields[1]),
        "name": fields[2],
        "color": int(fields[3]) if len(fields) == 4 else None,
    }


class MockPce:
    def __init__(self, args):
        self.args = args
        self.logfile = open(args.log, "a", buffering=1)
        self.sock = None
        self.conn = None
        self.sync_done = False
        self.initiated = False
        self.next_srp_id = 1
        self.srp_to_name = {}
        self.plsp_by_name = {}
        self.command_pos = 0
        self.deferred_removes = []

        self.policies = list(args.policy or [])
        if args.endpoint:
            self.policies.insert(
                0,
                {
                    "endpoint": args.endpoint,
                    "label": args.label,
                    "name": args.name,
                    "color": args.color,
                },
            )

    def log(self, text):
        self.logfile.write("%.3f %s\n" % (time.time(), text))

    # ------------------------------------------------------------------
    # Message builders
    #
    # Every builder assembles the exact RFC wire layout with
    # struct.pack().  The format strings read left to right, one field
    # per letter: ">" = network (big-endian) byte order, "B" = 1 byte,
    # "H" = 2 bytes, "I" = 4 bytes.  Fields packed into part of a byte
    # or word (flags, PLSP-ID) are shifted/OR'd together first, since
    # pack() only handles whole-byte fields.
    # ------------------------------------------------------------------
    @staticmethod
    def _obj(oclass, otype, body):
        """Wrap body in the PCEP common object header (RFC 5440 S7.2):

            Object-Class (1) | Object-Type(4 bits)+flags(4 bits) (1) |
            Object Length (2, includes this header)
        """
        # object header: class(1) type<<4(1) total-length(2)
        return struct.pack(">BBH", oclass, otype << 4, 4 + len(body)) + body

    @staticmethod
    def _msg(mtype, body):
        """Wrap body in the PCEP common message header (RFC 5440 S6.1):

            Version(3 bits)+Flags(5 bits) (1) | Message-Type (1) |
            Message-Length (2, includes this header)
        """
        # message header: version/flags(1) type(1) total-length(2)
        return struct.pack(">BBH", PCEP_VERSION_BYTE, mtype, 4 + len(body)) + body

    def build_open(self):
        """Open message (RFC 5440 S6.2), one OPEN object:

            <Common Header>   type 1 (Open)
            <OPEN>            Ver/Flags(1) Keepalive(1) DeadTimer(1) SID(1)
              <STATEFUL-PCE-CAPABILITY>   RFC 8231: U|I flag bits
              <SR-PCE-CAPABILITY>         RFC 8664: reserved/flags/MSD
              <PATH-SETUP-TYPE-CAPABILITY> RFC 8408: PST list = [SR-TE]

        pathd requires at least one TLV in the Open and needs the
        STATEFUL-PCE-CAPABILITY U bit to send any PCRpt at all.
        """
        # TLV header type(2) len(2) + flags word(4): U|I = 0x05
        tlvs = struct.pack(">HHI", TLV_STATEFUL_CAP, 4, 0x05)
        # TLV header type(2) len(2) + reserved(1) flags(2 as two B) MSD(1),
        # all zero
        tlvs += struct.pack(">HHBBBB", TLV_SR_CAP, 4, 0, 0, 0, 0)
        # TLV header type(2) len(2) + reserved(2) NumPSTs(1) PST(1)=1(SR-TE)
        # + sub-TLV padding(4)
        tlvs += struct.pack(">HHBBBBBBBB", TLV_PST_CAP, 8, 0, 0, 0, 1, 1, 0, 0, 0)
        # OPEN object body: version/flags(1) keepalive(1)=30
        # deadtimer(1)=120 session-id(1)=1
        body = struct.pack(">BBBB", PCEP_VERSION_BYTE, 30, 120, 1)
        return self._msg(MSG_OPEN, self._obj(CLASS_OPEN, 1, body + tlvs))

    def build_keepalive(self):
        """Keepalive message (RFC 5440 S6.3): the common header alone."""
        return self._msg(MSG_KEEPALIVE, b"")

    def build_initiate(self, policy, srp_id):
        """PCInitiate message (RFC 8281 S5.1) creating one SR policy:

            <Common Header>   type 12 (PCInitiate)
            <SRP>             Flags(4, R clear = create) SRP-ID(4)
              <PATH-SETUP-TYPE>           PST 1 = SR-TE (RFC 8408)
            <LSP>             PLSP-ID(20 bits)=0 (create) |
                              Flags(12 bits)=D|A|C
              <SYMBOLIC-PATH-NAME>        the policy name, 4-byte padded
            <END-POINTS>      source addr (PCC), destination addr
                              (object type 1 = IPv4, 2 = IPv6)
            <ERO>             one SR subobject (RFC 8664 S4.3.1):
                              label-only SID, NAI absent
            [<VENDOR-INFO>]   Cisco enterprise TLV carrying the color

        pathd reads the policy color from the VENDOR-INFO object;
        without it every initiated policy gets INITIATED_POLICY_COLOR
        (1).
        """
        # PATH-SETUP-TYPE TLV: type(2) len(2) + reserved(3) PST(1)=1
        srp_tlv = struct.pack(">HHBBBB", TLV_PATH_SETUP_TYPE, 4, 0, 0, 0, 1)
        # SRP object body: flags(4)=0 (R clear = create) srp-id(4)
        srp = self._obj(CLASS_SRP, 1, struct.pack(">II", 0, srp_id) + srp_tlv)

        name = policy["name"].encode()
        pad = (-len(name)) % 4
        # SYMBOLIC-PATH-NAME TLV: type(2) len(2) + name, padded to 4
        lsp_tlv = (
            struct.pack(">HH", TLV_SYMBOLIC_NAME, len(name)) + name + b"\x00" * pad
        )
        # LSP object word: PLSP-ID in the top 20 bits (0 = create),
        # flags in the low 12 (0x81 = Delegate|Administrative)
        lsp = self._obj(CLASS_LSP, 1, struct.pack(">I", (0 << 12) | 0x81) + lsp_tlv)

        # END-POINTS body: raw source then destination address,
        # object type picked by the endpoint's family
        if ":" in policy["endpoint"]:
            ep_body = socket.inet_pton(socket.AF_INET6, self.args.pcc_address6)
            ep_body += socket.inet_pton(socket.AF_INET6, policy["endpoint"])
            ep = self._obj(CLASS_ENDPOINTS, 2, ep_body)
        else:
            ep_body = socket.inet_aton(self.args.pcc_address)
            ep_body += socket.inet_aton(policy["endpoint"])
            ep = self._obj(CLASS_ENDPOINTS, 1, ep_body)

        # SR-ERO subobject: the 20-bit MPLS label sits in the TOP bits
        # of the 32-bit SID field (RFC 8664), hence the shift
        sid = (policy["label"] << 12) & 0xFFFFFFFF
        # subobject: type(1)=0x24(SR) length(1)=8 NT/flags(1)=0(NAI
        # absent) flags(1)=0x09(F|M: no NAI, SID is an MPLS label) SID(4)
        sub = struct.pack(">BBBBI", 0x24, 8, 0x00, 0x09, sid)
        ero = self._obj(CLASS_ERO, 1, sub)

        msg = srp + lsp + ep + ero

        if policy["color"] is not None:
            # VENDOR-INFO body: enterprise(4)=9(Cisco)
            # enterprise-specific-info(4)=color-type color-value(4)
            vendor = self._obj(
                CLASS_VENDOR_INFO,
                1,
                struct.pack(
                    ">III",
                    VENDOR_ENTERPRISE_CISCO,
                    VENDOR_ESI_COLOR,
                    policy["color"],
                ),
            )
            msg += vendor

        return self._msg(MSG_INITIATE, msg)

    def build_remove(self, name, plsp_id, srp_id):
        """PCInitiate removal (RFC 8281 S5.4), R flag set:

            <Common Header>   type 12 (PCInitiate)
            <SRP>             Flags(4, R set = remove) SRP-ID(4)
            <LSP>             PLSP-ID(20 bits) = the PCC's id for the
                              path | Flags(12 bits) = D
              <SYMBOLIC-PATH-NAME>        repeated for good measure

        A removal is addressed by the PLSP-ID the PCC assigned (learned
        from its PCRpt); no END-POINTS/ERO are carried.
        """
        # SRP object body: flags(4)=1 (R set = remove) srp-id(4)
        srp = self._obj(CLASS_SRP, 1, struct.pack(">II", 0x00000001, srp_id))

        encoded = name.encode()
        pad = (-len(encoded)) % 4
        # SYMBOLIC-PATH-NAME TLV: type(2) len(2) + name, padded to 4
        lsp_tlv = (
            struct.pack(">HH", TLV_SYMBOLIC_NAME, len(encoded))
            + encoded
            + b"\x00" * pad
        )
        # LSP object word: PLSP-ID in the top 20 bits, flags in the low
        # 12 (0x01 = Delegate)
        lsp = self._obj(
            CLASS_LSP, 1, struct.pack(">I", (plsp_id << 12) | 0x01) + lsp_tlv
        )

        return self._msg(MSG_INITIATE, srp + lsp)

    # ------------------------------------------------------------------
    # Receive path
    # ------------------------------------------------------------------
    def handle_report(self, body):
        """Walk a PCRpt's objects (the mirror of the builders above):
        each starts with the common object header class(1) type(1)
        length(2); the SRP object carries the echoed SRP-ID at body
        offset 4, the LSP object packs PLSP-ID(20 bits)|flags(12 bits)
        into its first word."""
        index = 0
        srp_id = None
        while index + 4 <= len(body):
            oclass = body[index]
            # object header length field: bytes 2-3, includes the header
            olen = struct.unpack(">H", body[index + 2 : index + 4])[0]
            if olen < 4 or index + olen > len(body):
                break
            if oclass == CLASS_SRP and index + 12 <= len(body):
                # SRP body: flags(4) then srp-id(4)
                srp_id = struct.unpack(">I", body[index + 8 : index + 12])[0]
            if oclass == CLASS_LSP and index + 8 <= len(body):
                # LSP first word: PLSP-ID(20 bits) | flags(12 bits)
                word0 = struct.unpack(">I", body[index + 4 : index + 8])[0]
                plsp_id = word0 >> 12
                flags = word0 & 0xFF
                oper = (flags >> 4) & 0x07
                self.log(
                    "REPORT plsp-id=%u flags=0x%02x oper=%u srp=%s"
                    % (plsp_id, flags, oper, srp_id)
                )
                if plsp_id == 0 and not flags & LSP_FLAG_SYNC:
                    self.sync_done = True
                # A report echoing one of our SRP-IDs tells us the
                # PLSP-ID the PCC assigned to that policy.
                if srp_id in self.srp_to_name and plsp_id != 0:
                    name = self.srp_to_name[srp_id]
                    if name not in self.plsp_by_name:
                        self.plsp_by_name[name] = plsp_id
                        self.log("MAPPED name=%s plsp-id=%u" % (name, plsp_id))
            index += olen

    def handle_error(self, body):
        """Walk a PCErr's objects: the PCEP-ERROR object (class 13)
        carries error-type and error-value in the 3rd and 4th bytes of
        its body; an SRP object echoing the failed request's SRP-ID
        may precede it, which lets us name the policy the error is
        about."""
        index = 0
        srp_id = None
        while index + 4 <= len(body):
            oclass = body[index]
            olen = struct.unpack(">H", body[index + 2 : index + 4])[0]
            if olen < 4 or index + olen > len(body):
                break
            if oclass == CLASS_SRP and index + 12 <= len(body):
                # SRP body: flags(4) then srp-id(4)
                srp_id = struct.unpack(">I", body[index + 8 : index + 12])[0]
            if oclass == CLASS_ERROR and index + 8 <= len(body):
                # PCEP-ERROR body: reserved(1) flags(1) type(1) value(1)
                error_type = body[index + 6]
                error_value = body[index + 7]
                self.log(
                    "RECV-ERROR type=%u value=%u srp=%s name=%s"
                    % (
                        error_type,
                        error_value,
                        srp_id,
                        self.srp_to_name.get(srp_id),
                    )
                )
            index += olen

    def handle_message(self, mtype, body):
        if mtype == MSG_OPEN:
            self.log("RECV-OPEN")
        elif mtype == MSG_KEEPALIVE:
            self.log("RECV-KEEPALIVE")
        elif mtype == MSG_REPORT:
            self.handle_report(body)
        elif mtype == MSG_ERROR:
            self.handle_error(body)
        else:
            self.log("RECV-TYPE-%u" % mtype)

    def poll_commands(self):
        """Act on new lines in the command file:

        remove <name>
        add <endpoint,label,name[,color]>

        add is only meaningful once the PCC's state-sync is done (pathd
        silently discards earlier PCInitiates); the tests churn well
        after session establishment.
        """
        if not self.args.command_file:
            return
        if not os.path.exists(self.args.command_file):
            return

        with open(self.args.command_file) as cmds:
            lines = cmds.readlines()

        # Retry removes whose PLSP-ID mapping had not arrived yet: the
        # PCRpt that (re-)establishes it can still be in flight when the
        # remove command lands.
        deferred = self.deferred_removes
        self.deferred_removes = []
        for name in deferred:
            self.send_remove(name)

        for line in lines[self.command_pos :]:
            self.command_pos += 1
            fields = line.split()
            if len(fields) == 2 and fields[0] == "remove":
                self.send_remove(fields[1])
            elif len(fields) == 2 and fields[0] == "add":
                try:
                    policy = parse_policy(fields[1])
                except argparse.ArgumentTypeError:
                    self.log("ADD-BAD-SPEC %s" % fields[1])
                    continue
                srp_id = self.next_srp_id
                self.next_srp_id += 1
                self.srp_to_name[srp_id] = policy["name"]
                self.conn.sendall(self.build_initiate(policy, srp_id))
                self.log(
                    "ADD-SENT endpoint=%s label=%u name=%s color=%s"
                    % (
                        policy["endpoint"],
                        policy["label"],
                        policy["name"],
                        policy["color"],
                    )
                )

    def send_remove(self, name):
        """Send a PCInitiate R-flag remove, deferring until the name's
        PLSP-ID mapping is known."""
        if name not in self.plsp_by_name:
            self.log("REMOVE-DEFERRED name=%s" % name)
            self.deferred_removes.append(name)
            return
        srp_id = self.next_srp_id
        self.next_srp_id += 1
        plsp_id = self.plsp_by_name.pop(name)
        self.conn.sendall(self.build_remove(name, plsp_id, srp_id))
        self.log("REMOVE-SENT name=%s plsp-id=%u" % (name, plsp_id))

    def keepalive_loop(self):
        while True:
            time.sleep(10)
            try:
                self.conn.sendall(self.build_keepalive())
            except OSError:
                return

    def run(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.args.address, self.args.port))
        self.sock.listen(1)
        self.log("LISTENING %s:%u" % (self.args.address, self.args.port))

        self.conn, peer = self.sock.accept()
        self.log("CONNECT %s:%u" % peer)

        # Both Open-first and Keepalive-first orders are accepted by
        # pceplib; send both back to back.
        self.conn.sendall(self.build_open())
        self.conn.sendall(self.build_keepalive())
        self.log("SENT-OPEN-KEEPALIVE")

        threading.Thread(target=self.keepalive_loop, daemon=True).start()

        buffer = b""
        while True:
            readable, _, _ = select.select([self.conn], [], [], 1.0)

            # Drain and process input BEFORE acting on commands, so a
            # remove issued right after its policy's PCRpt does not race
            # the mapping that report establishes.
            if readable:
                data = self.conn.recv(65536)
                if not data:
                    self.log("DISCONNECT")
                    return
                buffer += data
                while len(buffer) >= 4:
                    # common message header length field: bytes 2-3,
                    # includes the 4-byte header itself
                    mlen = struct.unpack(">H", buffer[2:4])[0]
                    if mlen < 4 or len(buffer) < mlen:
                        break
                    self.handle_message(buffer[1], buffer[4:mlen])
                    buffer = buffer[mlen:]

            self.poll_commands()

            if self.sync_done and not self.initiated:
                self.initiated = True
                for policy in self.policies:
                    srp_id = self.next_srp_id
                    self.next_srp_id += 1
                    self.srp_to_name[srp_id] = policy["name"]
                    self.conn.sendall(self.build_initiate(policy, srp_id))
                    self.log(
                        "INITIATE-SENT endpoint=%s label=%u name=%s color=%s"
                        % (
                            policy["endpoint"],
                            policy["label"],
                            policy["name"],
                            policy["color"],
                        )
                    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4189)
    parser.add_argument("--pcc-address", default="1.1.1.1")
    parser.add_argument("--pcc-address6", default="2001:db8::1")
    parser.add_argument("--endpoint")
    parser.add_argument("--label", type=int)
    parser.add_argument("--name", default="test-steer")
    parser.add_argument("--color", type=int)
    parser.add_argument(
        "--policy",
        action="append",
        type=parse_policy,
        help="endpoint,label,name[,color]; may be repeated",
    )
    parser.add_argument(
        "--command-file",
        help="poll this file for commands, one per line: 'remove <name>' "
        "or 'add <endpoint,label,name[,color]>'",
    )
    parser.add_argument("--log", required=True)
    args = parser.parse_args()

    if not args.policy and not args.endpoint:
        parser.error("at least one --policy or --endpoint is required")
    if args.endpoint and args.label is None:
        parser.error("--endpoint requires --label")

    MockPce(args).run()


if __name__ == "__main__":
    main()
