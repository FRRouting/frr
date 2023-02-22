#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# December 22 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021-2022, LabN Consulting, L.L.C.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#

import argparse
import asyncio
import errno
import logging
import socket
import struct
import sys
from asyncio import Event, Lock
from ipaddress import ip_address as ip

FMT_APIMSGHDR = ">BBHL"
FMT_APIMSGHDR_SIZE = struct.calcsize(FMT_APIMSGHDR)

FMT_LSA_FILTER = ">HBB"  # + plus x"I" areas
LSAF_ORIGIN_NON_SELF = 0
LSAF_ORIGIN_SELF = 1
LSAF_ORIGIN_ANY = 2

FMT_LSA_HEADER = ">HBBIILHH"
FMT_LSA_HEADER_SIZE = struct.calcsize(FMT_LSA_HEADER)

# ------------------------
# Messages to OSPF daemon.
# ------------------------

MSG_REGISTER_OPAQUETYPE = 1
MSG_UNREGISTER_OPAQUETYPE = 2
MSG_REGISTER_EVENT = 3
MSG_SYNC_LSDB = 4
MSG_ORIGINATE_REQUEST = 5
MSG_DELETE_REQUEST = 6
MSG_SYNC_REACHABLE = 7
MSG_SYNC_ISM = 8
MSG_SYNC_NSM = 9
MSG_SYNC_ROUTER_ID = 19

smsg_info = {
    MSG_REGISTER_OPAQUETYPE: ("REGISTER_OPAQUETYPE", "BBxx"),
    MSG_UNREGISTER_OPAQUETYPE: ("UNREGISTER_OPAQUETYPE", "BBxx"),
    MSG_REGISTER_EVENT: ("REGISTER_EVENT", FMT_LSA_FILTER),
    MSG_SYNC_LSDB: ("SYNC_LSDB", FMT_LSA_FILTER),
    MSG_ORIGINATE_REQUEST: ("ORIGINATE_REQUEST", ">II" + FMT_LSA_HEADER[1:]),
    MSG_DELETE_REQUEST: ("DELETE_REQUEST", ">IBBxBL"),
    MSG_SYNC_REACHABLE: ("MSG_SYNC_REACHABLE", ""),
    MSG_SYNC_ISM: ("MSG_SYNC_ISM", ""),
    MSG_SYNC_NSM: ("MSG_SYNC_NSM", ""),
    MSG_SYNC_ROUTER_ID: ("MSG_SYNC_ROUTER_ID", ""),
}

# OSPF API MSG Delete Flag.
OSPF_API_DEL_ZERO_LEN_LSA = 0x01  # send withdrawal with no LSA data

# --------------------------
# Messages from OSPF daemon.
# --------------------------

MSG_REPLY = 10
MSG_READY_NOTIFY = 11
MSG_LSA_UPDATE_NOTIFY = 12
MSG_LSA_DELETE_NOTIFY = 13
MSG_NEW_IF = 14
MSG_DEL_IF = 15
MSG_ISM_CHANGE = 16
MSG_NSM_CHANGE = 17
MSG_REACHABLE_CHANGE = 18
MSG_ROUTER_ID_CHANGE = 20

amsg_info = {
    MSG_REPLY: ("REPLY", "bxxx"),
    MSG_READY_NOTIFY: ("READY_NOTIFY", ">BBxxI"),
    MSG_LSA_UPDATE_NOTIFY: ("LSA_UPDATE_NOTIFY", ">IIBxxx" + FMT_LSA_HEADER[1:]),
    MSG_LSA_DELETE_NOTIFY: ("LSA_DELETE_NOTIFY", ">IIBxxx" + FMT_LSA_HEADER[1:]),
    MSG_NEW_IF: ("NEW_IF", ">II"),
    MSG_DEL_IF: ("DEL_IF", ">I"),
    MSG_ISM_CHANGE: ("ISM_CHANGE", ">IIBxxx"),
    MSG_NSM_CHANGE: ("NSM_CHANGE", ">IIIBxxx"),
    MSG_REACHABLE_CHANGE: ("REACHABLE_CHANGE", ">HH"),
    MSG_ROUTER_ID_CHANGE: ("ROUTER_ID_CHANGE", ">I"),
}

OSPF_API_OK = 0
OSPF_API_NOSUCHINTERFACE = -1
OSPF_API_NOSUCHAREA = -2
OSPF_API_NOSUCHLSA = -3
OSPF_API_ILLEGALLSATYPE = -4
OSPF_API_OPAQUETYPEINUSE = -5
OSPF_API_OPAQUETYPENOTREGISTERED = -6
OSPF_API_NOTREADY = -7
OSPF_API_NOMEMORY = -8
OSPF_API_ERROR = -9
OSPF_API_UNDEF = -10

msg_errname = {
    OSPF_API_OK: "OSPF_API_OK",
    OSPF_API_NOSUCHINTERFACE: "OSPF_API_NOSUCHINTERFACE",
    OSPF_API_NOSUCHAREA: "OSPF_API_NOSUCHAREA",
    OSPF_API_NOSUCHLSA: "OSPF_API_NOSUCHLSA",
    OSPF_API_ILLEGALLSATYPE: "OSPF_API_ILLEGALLSATYPE",
    OSPF_API_OPAQUETYPEINUSE: "OSPF_API_OPAQUETYPEINUSE",
    OSPF_API_OPAQUETYPENOTREGISTERED: "OSPF_API_OPAQUETYPENOTREGISTERED",
    OSPF_API_NOTREADY: "OSPF_API_NOTREADY",
    OSPF_API_NOMEMORY: "OSPF_API_NOMEMORY",
    OSPF_API_ERROR: "OSPF_API_ERROR",
    OSPF_API_UNDEF: "OSPF_API_UNDEF",
}

# msg_info = {**smsg_info, **amsg_info}
msg_info = {}
msg_info.update(smsg_info)
msg_info.update(amsg_info)
msg_name = {k: v[0] for k, v in msg_info.items()}
msg_fmt = {k: v[1] for k, v in msg_info.items()}
msg_size = {k: struct.calcsize(v) for k, v in msg_fmt.items()}


def api_msgname(mt):
    return msg_name.get(mt, str(mt))


def api_errname(ecode):
    return msg_errname.get(ecode, str(ecode))


# -------------------
# API Semantic Errors
# -------------------


class APIError(Exception):
    pass


class MsgTypeError(Exception):
    pass


class SeqNumError(Exception):
    pass


# ---------
# LSA Types
# ---------

LSA_TYPE_UNKNOWN = 0
LSA_TYPE_ROUTER = 1
LSA_TYPE_NETWORK = 2
LSA_TYPE_SUMMARY = 3
LSA_TYPE_ASBR_SUMMARY = 4
LSA_TYPE_AS_EXTERNAL = 5
LSA_TYPE_GROUP_MEMBER = 6
LSA_TYPE_AS_NSSA = 7
LSA_TYPE_EXTERNAL_ATTRIBUTES = 8
LSA_TYPE_OPAQUE_LINK = 9
LSA_TYPE_OPAQUE_AREA = 10
LSA_TYPE_OPAQUE_AS = 11


def lsa_typename(lsa_type):
    names = {
        LSA_TYPE_ROUTER: "LSA:ROUTER",
        LSA_TYPE_NETWORK: "LSA:NETWORK",
        LSA_TYPE_SUMMARY: "LSA:SUMMARY",
        LSA_TYPE_ASBR_SUMMARY: "LSA:ASBR_SUMMARY",
        LSA_TYPE_AS_EXTERNAL: "LSA:AS_EXTERNAL",
        LSA_TYPE_GROUP_MEMBER: "LSA:GROUP_MEMBER",
        LSA_TYPE_AS_NSSA: "LSA:AS_NSSA",
        LSA_TYPE_EXTERNAL_ATTRIBUTES: "LSA:EXTERNAL_ATTRIBUTES",
        LSA_TYPE_OPAQUE_LINK: "LSA:OPAQUE_LINK",
        LSA_TYPE_OPAQUE_AREA: "LSA:OPAQUE_AREA",
        LSA_TYPE_OPAQUE_AS: "LSA:OPAQUE_AS",
    }
    return names.get(lsa_type, str(lsa_type))


# ------------------------------
# Interface State Machine States
# ------------------------------

ISM_DEPENDUPON = 0
ISM_DOWN = 1
ISM_LOOPBACK = 2
ISM_WAITING = 3
ISM_POINTTOPOINT = 4
ISM_DROTHER = 5
ISM_BACKUP = 6
ISM_DR = 7


def ism_name(state):
    names = {
        ISM_DEPENDUPON: "ISM_DEPENDUPON",
        ISM_DOWN: "ISM_DOWN",
        ISM_LOOPBACK: "ISM_LOOPBACK",
        ISM_WAITING: "ISM_WAITING",
        ISM_POINTTOPOINT: "ISM_POINTTOPOINT",
        ISM_DROTHER: "ISM_DROTHER",
        ISM_BACKUP: "ISM_BACKUP",
        ISM_DR: "ISM_DR",
    }
    return names.get(state, str(state))


# -----------------------------
# Neighbor State Machine States
# -----------------------------

NSM_DEPENDUPON = 0
NSM_DELETED = 1
NSM_DOWN = 2
NSM_ATTEMPT = 3
NSM_INIT = 4
NSM_TWOWAY = 5
NSM_EXSTART = 6
NSM_EXCHANGE = 7
NSM_LOADING = 8
NSM_FULL = 9


def nsm_name(state):
    names = {
        NSM_DEPENDUPON: "NSM_DEPENDUPON",
        NSM_DELETED: "NSM_DELETED",
        NSM_DOWN: "NSM_DOWN",
        NSM_ATTEMPT: "NSM_ATTEMPT",
        NSM_INIT: "NSM_INIT",
        NSM_TWOWAY: "NSM_TWOWAY",
        NSM_EXSTART: "NSM_EXSTART",
        NSM_EXCHANGE: "NSM_EXCHANGE",
        NSM_LOADING: "NSM_LOADING",
        NSM_FULL: "NSM_FULL",
    }
    return names.get(state, str(state))


class WithNothing:
    "An object that does nothing when used with `with` statement."

    async def __aenter__(self):
        return

    async def __aexit__(self, *args, **kwargs):
        return


# --------------
# Client Classes
# --------------


class OspfApiClient:
    def __str__(self):
        return "OspfApiClient({})".format(self.server)

    @staticmethod
    def _get_bound_sockets(port):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        try:
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s1.bind(("", port))
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            try:
                s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s2.bind(("", port + 1))
                return s1, s2
            except Exception:
                s2.close()
                raise
        except Exception:
            s1.close()
            raise

    def __init__(self, server="localhost", handlers=None):
        """A client connection to OSPF Daemon using the OSPF API

        The client object is not created in a connected state.  To connect to the server
        the `connect` method should be called.  If an error is encountered when sending
        messages to the server an exception will be raised and the connection will be
        closed.  When this happens `connect` may be called again to restore the
        connection.

        Args:
            server: hostname or IP address of server default is "localhost"
            handlers: dict of message handlers, the key is the API message
                type, the value is a function. The functions signature is:
                `handler(msg_type, msg, msg_extra, *params)`, where `msg` is the
                message data after the API header, `*params` will be the
                unpacked message values, and msg_extra are any bytes beyond the
                fixed parameters of the message.
        Raises:
            Will raise exceptions for failures with various `socket` modules
            functions such as `socket.socket`, `socket.setsockopt`, `socket.bind`.
        """
        self._seq = 0
        self._s = None
        self._as = None
        self._ls = None
        self._ar = self._r = self._w = None
        self.server = server
        self.handlers = handlers if handlers is not None else dict()
        self.write_lock = Lock()

        # try and get consecutive 2 ports
        PORTSTART = 49152
        PORTEND = 65534
        for port in range(PORTSTART, PORTEND + 2, 2):
            try:
                logging.debug("%s: binding to ports %s, %s", self, port, port + 1)
                self._s, self._ls = self._get_bound_sockets(port)
                break
            except OSError as error:
                if error.errno != errno.EADDRINUSE or port == PORTEND:
                    logging.warning("%s: binding port %s error %s", self, port, error)
                    raise
                logging.debug("%s: ports %s, %s in use.", self, port, port + 1)
        else:
            assert False, "Should not reach this code execution point"

    async def _connect_locked(self):
        logging.debug("%s: connect to OSPF API", self)

        loop = asyncio.get_event_loop()

        self._ls.listen()
        try:
            logging.debug("%s: connecting sync socket to server", self)
            await loop.sock_connect(self._s, (self.server, 2607))

            logging.debug("%s: accepting connect from server", self)
            self._as, _ = await loop.sock_accept(self._ls)
        except Exception:
            await self._close_locked()
            raise

        logging.debug("%s: success", self)
        self._r, self._w = await asyncio.open_connection(sock=self._s)
        self._ar, _ = await asyncio.open_connection(sock=self._as)
        self._seq = 1

    async def connect(self):
        async with self.write_lock:
            await self._connect_locked()

    @property
    def closed(self):
        "True if the connection is closed."
        return self._seq == 0

    async def _close_locked(self):
        logging.debug("%s: closing", self)
        if self._s:
            if self._w:
                self._w.close()
                await self._w.wait_closed()
                self._w = None
            else:
                self._s.close()
            self._s = None
            self._r = None
        assert self._w is None
        if self._as:
            self._as.close()
            self._as = None
            self._ar = None
        if self._ls:
            self._ls.close()
            self._ls = None
        self._seq = 0

    async def close(self):
        async with self.write_lock:
            await self._close_locked()

    @staticmethod
    async def _msg_read(r, expseq=-1):
        """Read an OSPF API message from the socket `r`

        Args:
            r: socket to read msg from
            expseq: sequence number to expect or -1 for any.
        Raises:
            Will raise exceptions for failures with various `socket` modules,
            Additionally may raise SeqNumError if unexpected seqnum is received.
        """
        try:
            mh = await r.readexactly(FMT_APIMSGHDR_SIZE)
            v, mt, l, seq = struct.unpack(FMT_APIMSGHDR, mh)
            if v != 1:
                raise Exception("received unexpected OSPF API version {}".format(v))
            if expseq == -1:
                logging.debug("_msg_read: got seq: 0x%x on async read", seq)
            elif seq != expseq:
                raise SeqNumError("rx {} != {}".format(seq, expseq))
            msg = await r.readexactly(l) if l else b""
            return mt, msg
        except asyncio.IncompleteReadError:
            raise EOFError

    async def msg_read(self):
        """Read a message from the async notify channel.

        Raises:
            May raise exceptions for failures with various `socket` modules.
        """
        return await OspfApiClient._msg_read(self._ar, -1)

    async def msg_send(self, mt, mp):
        """Send a message to OSPF API and wait for error code reply.

        Args:
            mt: the messaage type
            mp: the message payload
        Returns:
            error: an OSPF_API_XXX error code, 0 for OK.
        Raises:
            Raises SeqNumError if the synchronous reply is the wrong sequence number;
            MsgTypeError if the synchronous reply is not MSG_REPLY. Also,
            may raise exceptions for failures with various `socket` modules,

            The connection will be closed.
        """
        logging.debug("SEND: %s: sending %s seq 0x%x", self, api_msgname(mt), self._seq)
        mh = struct.pack(FMT_APIMSGHDR, 1, mt, len(mp), self._seq)

        seq = self._seq
        self._seq = seq + 1

        try:
            async with self.write_lock:
                self._w.write(mh + mp)
                await self._w.drain()
                mt, mp = await OspfApiClient._msg_read(self._r, seq)

            if mt != MSG_REPLY:
                raise MsgTypeError(
                    "rx {} != {}".format(api_msgname(mt), api_msgname(MSG_REPLY))
                )

            return struct.unpack(msg_fmt[MSG_REPLY], mp)[0]
        except Exception:
            # We've written data with a sequence number
            await self.close()
            raise

    async def msg_send_raises(self, mt, mp=b"\x00" * 4):
        """Send a message to OSPF API and wait for error code reply.

        Args:
            mt: the messaage type
            mp: the message payload
        Raises:
            APIError if the server replies with an error.

            Also may raise exceptions for failures with various `socket` modules,
            as well as MsgTypeError if the synchronous reply is incorrect.
            The connection will be closed for these non-API error exceptions.
        """
        ecode = await self.msg_send(mt, mp)
        if ecode:
            raise APIError("{} error {}".format(api_msgname(mt), api_errname(ecode)))

    async def handle_async_msg(self, mt, msg):
        if mt not in msg_fmt:
            logging.debug("RECV: %s: unknown async msg type %s", self, mt)
            return

        fmt = msg_fmt[mt]
        sz = msg_size[mt]
        tup = struct.unpack(fmt, msg[:sz])
        extra = msg[sz:]

        if mt not in self.handlers:
            logging.debug(
                "RECV: %s: no handlers for msg type %s", self, api_msgname(mt)
            )
            return

        logging.debug("RECV: %s: calling handler for %s", self, api_msgname(mt))
        await self.handlers[mt](mt, msg, extra, *tup)

    #
    # Client to Server Messaging
    #
    @staticmethod
    def lsa_type_mask(*lsa_types):
        "Return a 16 bit mask for each LSA type passed."
        if not lsa_types:
            return 0xFFFF
        mask = 0
        for t in lsa_types:
            assert 0 < t < 16, "LSA type {} out of range [1, 15]".format(t)
            mask |= 1 << t
        return mask

    @staticmethod
    def lsa_filter(origin, areas, lsa_types):
        """Return an LSA filter.

        Return the filter message bytes based on `origin` the `areas` list and the LSAs
        types in the `lsa_types` list.
        """
        mask = OspfApiClient.lsa_type_mask(*lsa_types)
        narea = len(areas)
        fmt = FMT_LSA_FILTER + ("{}I".format(narea) if narea else "")
        # lsa type mask, origin, number of areas, each area
        return struct.pack(fmt, mask, origin, narea, *areas)

    async def req_lsdb_sync(self):
        "Register for all LSA notifications and request an LSDB synchronoization."
        logging.debug("SEND: %s: request LSDB events", self)
        mp = OspfApiClient.lsa_filter(LSAF_ORIGIN_ANY, [], [])
        await self.msg_send_raises(MSG_REGISTER_EVENT, mp)

        logging.debug("SEND: %s: request LSDB sync", self)
        await self.msg_send_raises(MSG_SYNC_LSDB, mp)

    async def req_reachable_routers(self):
        "Request a dump of all reachable routers."
        logging.debug("SEND: %s: request reachable changes", self)
        await self.msg_send_raises(MSG_SYNC_REACHABLE)

    async def req_ism_states(self):
        "Request a dump of the current ISM states of all interfaces."
        logging.debug("SEND: %s: request ISM changes", self)
        await self.msg_send_raises(MSG_SYNC_ISM)

    async def req_nsm_states(self):
        "Request a dump of the current NSM states of all neighbors."
        logging.debug("SEND: %s: request NSM changes", self)
        await self.msg_send_raises(MSG_SYNC_NSM)

    async def req_router_id_sync(self):
        "Request a dump of the current NSM states of all neighbors."
        logging.debug("SEND: %s: request router ID sync", self)
        await self.msg_send_raises(MSG_SYNC_ROUTER_ID)


class OspfOpaqueClient(OspfApiClient):
    """A client connection to OSPF Daemon for manipulating Opaque LSA data.

    The client object is not created in a connected state.  To connect to the server
    the `connect` method should be called.  If an error is encountered when sending
    messages to the server an exception will be raised and the connection will be
    closed.  When this happens `connect` may be called again to restore the
    connection.

    Args:
        server: hostname or IP address of server default is "localhost"
        wait_ready: if True then wait for OSPF to signal ready, in newer versions
            FRR ospfd is always ready so this overhead can be skipped.
            default is False.

    Raises:
        Will raise exceptions for failures with various `socket` modules
        functions such as `socket.socket`, `socket.setsockopt`, `socket.bind`.
    """

    def __init__(self, server="localhost", wait_ready=False):
        handlers = {
            MSG_LSA_UPDATE_NOTIFY: self._lsa_change_msg,
            MSG_LSA_DELETE_NOTIFY: self._lsa_change_msg,
            MSG_NEW_IF: self._if_msg,
            MSG_DEL_IF: self._if_msg,
            MSG_ISM_CHANGE: self._if_change_msg,
            MSG_NSM_CHANGE: self._nbr_change_msg,
            MSG_REACHABLE_CHANGE: self._reachable_msg,
            MSG_ROUTER_ID_CHANGE: self._router_id_msg,
        }
        if wait_ready:
            handlers[MSG_READY_NOTIFY] = self._ready_msg

        super().__init__(server, handlers)

        self.wait_ready = wait_ready
        self.ready_lock = Lock() if wait_ready else WithNothing()
        self.ready_cond = {
            LSA_TYPE_OPAQUE_LINK: {},
            LSA_TYPE_OPAQUE_AREA: {},
            LSA_TYPE_OPAQUE_AS: {},
        }
        self.router_id = ip(0)
        self.router_id_change_cb = None

        self.lsid_seq_num = {}

        self.lsa_change_cb = None
        self.opaque_change_cb = {}

        self.reachable_routers = set()
        self.reachable_change_cb = None

        self.if_area = {}
        self.ism_states = {}
        self.ism_change_cb = None

        self.nsm_states = {}
        self.nsm_change_cb = None

    async def _register_opaque_data(self, lsa_type, otype):
        async with self.ready_lock:
            cond = self.ready_cond[lsa_type].get(otype)
            assert cond is None, "multiple registers for {} opaque-type {}".format(
                lsa_typename(lsa_type), otype
            )

            logging.debug("register %s opaque-type %s", lsa_typename(lsa_type), otype)

            mt = MSG_REGISTER_OPAQUETYPE
            mp = struct.pack(msg_fmt[mt], lsa_type, otype)
            await self.msg_send_raises(mt, mp)

            # If we are not waiting, mark ready for register check
            if not self.wait_ready:
                self.ready_cond[lsa_type][otype] = True

    async def _handle_msg_loop(self):
        try:
            logging.debug("entering async msg handling loop")
            while True:
                mt, msg = await self.msg_read()
                if mt in amsg_info:
                    await self.handle_async_msg(mt, msg)
                else:
                    mts = api_msgname(mt)
                    logging.warning(
                        "ignoring unexpected msg: %s len: %s", mts, len(msg)
                    )
        except EOFError:
            logging.info("Got EOF from OSPF API server on async notify socket")
            return 2

    @staticmethod
    def _opaque_args(lsa_type, otype, oid, mp):
        lsid = (otype << 24) | oid
        return 0, 0, lsa_type, lsid, 0, 0, 0, FMT_LSA_HEADER_SIZE + len(mp)

    @staticmethod
    def _make_opaque_lsa(lsa_type, otype, oid, mp):
        # /* Make a new LSA from parameters */
        lsa = struct.pack(
            FMT_LSA_HEADER, *OspfOpaqueClient._opaque_args(lsa_type, otype, oid, mp)
        )
        lsa += mp
        return lsa

    async def _ready_msg(self, mt, msg, extra, lsa_type, otype, addr):
        assert self.wait_ready

        if lsa_type == LSA_TYPE_OPAQUE_LINK:
            e = "ifaddr {}".format(ip(addr))
        elif lsa_type == LSA_TYPE_OPAQUE_AREA:
            e = "area {}".format(ip(addr))
        else:
            e = ""
        logging.info(
            "RECV: %s ready notify for %s opaque-type %s%s",
            self,
            lsa_typename(lsa_type),
            otype,
            e,
        )

        # Signal all waiting senders they can send now.
        async with self.ready_lock:
            cond = self.ready_cond[lsa_type].get(otype)
            self.ready_cond[lsa_type][otype] = True

        if cond is True:
            logging.warning(
                "RECV: dup ready received for %s opaque-type %s",
                lsa_typename(lsa_type),
                otype,
            )
        elif cond:
            for evt in cond:
                evt.set()

    async def _if_msg(self, mt, msg, extra, *args):
        if mt == MSG_NEW_IF:
            ifaddr, aid = args
        else:
            assert mt == MSG_DEL_IF
            ifaddr, aid = args[0], 0
        logging.info(
            "RECV: %s ifaddr %s areaid %s", api_msgname(mt), ip(ifaddr), ip(aid)
        )

    async def _if_change_msg(self, mt, msg, extra, ifaddr, aid, state):
        ifaddr = ip(ifaddr)
        aid = ip(aid)

        logging.info(
            "RECV: %s ifaddr %s areaid %s state %s",
            api_msgname(mt),
            ifaddr,
            aid,
            ism_name(state),
        )

        self.if_area[ifaddr] = aid
        self.ism_states[ifaddr] = state

        if self.ism_change_cb:
            self.ism_change_cb(ifaddr, aid, state)

    async def _nbr_change_msg(self, mt, msg, extra, ifaddr, nbraddr, router_id, state):
        ifaddr = ip(ifaddr)
        nbraddr = ip(nbraddr)
        router_id = ip(router_id)

        logging.info(
            "RECV: %s ifaddr %s nbraddr %s router_id %s state %s",
            api_msgname(mt),
            ifaddr,
            nbraddr,
            router_id,
            nsm_name(state),
        )

        if ifaddr not in self.nsm_states:
            self.nsm_states[ifaddr] = {}
        self.nsm_states[ifaddr][(nbraddr, router_id)] = state

        if self.nsm_change_cb:
            self.nsm_change_cb(ifaddr, nbraddr, router_id, state)

    async def _lsa_change_msg(self, mt, msg, extra, ifaddr, aid, is_self, *ls_header):
        (
            lsa_age,  # ls_age,
            _,  # ls_options,
            lsa_type,
            ls_id,
            _,  # ls_adv_router,
            ls_seq,
            _,  # ls_cksum,
            ls_len,
        ) = ls_header

        otype = (ls_id >> 24) & 0xFF

        if mt == MSG_LSA_UPDATE_NOTIFY:
            ts = "update"
        else:
            assert mt == MSG_LSA_DELETE_NOTIFY
            ts = "delete"

        logging.info(
            "RECV: LSA %s msg for LSA %s in area %s seq 0x%x len %s age %s",
            ts,
            ip(ls_id),
            ip(aid),
            ls_seq,
            ls_len,
            lsa_age,
        )
        idx = (lsa_type, otype)

        pre_lsa_size = msg_size[mt] - FMT_LSA_HEADER_SIZE
        lsa = msg[pre_lsa_size:]

        if idx in self.opaque_change_cb:
            self.opaque_change_cb[idx](mt, ifaddr, aid, ls_header, extra, lsa)

        if self.lsa_change_cb:
            self.lsa_change_cb(mt, ifaddr, aid, ls_header, extra, lsa)

    async def _reachable_msg(self, mt, msg, extra, nadd, nremove):
        router_ids = struct.unpack(">{}I".format(nadd + nremove), extra)
        router_ids = [ip(x) for x in router_ids]
        logging.info(
            "RECV: %s added %s removed %s",
            api_msgname(mt),
            router_ids[:nadd],
            router_ids[nadd:],
        )
        self.reachable_routers |= set(router_ids[:nadd])
        self.reachable_routers -= set(router_ids[nadd:])
        logging.info("RECV: %s new set %s", api_msgname(mt), self.reachable_routers)

        if self.reachable_change_cb:
            logging.info("RECV: %s calling callback", api_msgname(mt))
            await self.reachable_change_cb(router_ids[:nadd], router_ids[nadd:])

    async def _router_id_msg(self, mt, msg, extra, router_id):
        router_id = ip(router_id)
        logging.info("RECV: %s router ID %s", api_msgname(mt), router_id)
        old_router_id = self.router_id
        if old_router_id == router_id:
            return

        self.router_id = router_id
        logging.info(
            "RECV: %s new router ID %s older router ID %s",
            api_msgname(mt),
            router_id,
            old_router_id,
        )

        if self.router_id_change_cb:
            logging.info("RECV: %s calling callback", api_msgname(mt))
            await self.router_id_change_cb(router_id, old_router_id)

    async def add_opaque_data(self, addr, lsa_type, otype, oid, data):
        """Add an instance of opaque data.

        Add an instance of opaque data. This call will register for the given
        LSA and opaque type if not already done.

        Args:
            addr: depends on lsa_type, LINK => ifaddr, AREA => area ID, AS => ignored
            lsa_type: LSA_TYPE_OPAQUE_{LINK,AREA,AS}
            otype: (octet) opaque type
            oid: (3 octets) ID of this opaque data
            data: the opaque data
        Raises:
            See `msg_send_raises`
        """
        assert self.ready_cond.get(lsa_type, {}).get(otype) is True, "Not Registered!"

        if lsa_type == LSA_TYPE_OPAQUE_LINK:
            ifaddr, aid = int(addr), 0
        elif lsa_type == LSA_TYPE_OPAQUE_AREA:
            ifaddr, aid = 0, int(addr)
        else:
            assert lsa_type == LSA_TYPE_OPAQUE_AS
            ifaddr, aid = 0, 0

        mt = MSG_ORIGINATE_REQUEST
        msg = struct.pack(
            msg_fmt[mt],
            ifaddr,
            aid,
            *OspfOpaqueClient._opaque_args(lsa_type, otype, oid, data),
        )
        msg += data
        await self.msg_send_raises(mt, msg)

    async def delete_opaque_data(self, addr, lsa_type, otype, oid, flags=0):
        """Delete an instance of opaque data.

        Delete an instance of opaque data. This call will register for the given
        LSA and opaque type if not already done.

        Args:
            addr: depends on lsa_type, LINK => ifaddr, AREA => area ID, AS => ignored
            lsa_type: LSA_TYPE_OPAQUE_{LINK,AREA,AS}
            otype: (octet) opaque type.
            oid: (3 octets) ID of this opaque data
            flags: (octet) optional flags (e.g., OSPF_API_DEL_ZERO_LEN_LSA, defaults to no flags)
        Raises:
            See `msg_send_raises`
        """
        assert self.ready_cond.get(lsa_type, {}).get(otype) is True, "Not Registered!"

        mt = MSG_DELETE_REQUEST
        mp = struct.pack(msg_fmt[mt], int(addr), lsa_type, otype, flags, oid)
        await self.msg_send_raises(mt, mp)

    async def is_registered(self, lsa_type, otype):
        """Determine if an (lsa_type, otype) tuple has been registered with FRR

        This determines if the type has been registered, but not necessarily if it is
        ready, if that is required use the `wait_opaque_ready` metheod.

        Args:
            lsa_type: LSA_TYPE_OPAQUE_{LINK,AREA,AS}
            otype: (octet) opaque type.
        """
        async with self.ready_lock:
            return self.ready_cond.get(lsa_type, {}).get(otype) is not None

    async def register_opaque_data(self, lsa_type, otype, callback=None):
        """Register intent to advertise opaque data.

        The application should wait for the async notificaiton that the server is
        ready to advertise the given opaque data type. The API currently only allows
        a single "owner" of each unique (lsa_type,otype). To wait call `wait_opaque_ready`

        Args:
            lsa_type: LSA_TYPE_OPAQUE_{LINK,AREA,AS}
            otype: (octet) opaque type.
            callback: if given, callback will be called when changes are received for
                LSA of the given (lsa_type, otype). The callbacks signature is:

                `callback(msg_type, ifaddr, area_id, lsa_header, data, lsa)`

                Args:
                    msg_type: MSG_LSA_UPDATE_NOTIFY or MSG_LSA_DELETE_NOTIFY
                    ifaddr: integer identifying an interface (by IP address)
                    area_id: integer identifying an area
                    lsa_header: the LSA header as an unpacked tuple (fmt: ">HBBIILHH")
                    data: the opaque data that follows the LSA header
                    lsa: the octets of the full lsa
        Raises:
            See `msg_send_raises`
        """
        assert not await self.is_registered(
            lsa_type, otype
        ), "Registering registered type"

        if callback:
            self.opaque_change_cb[(lsa_type, otype)] = callback
        elif (lsa_type, otype) in self.opaque_change_cb:
            logging.warning(
                "OSPFCLIENT: register: removing callback for %s opaque-type %s",
                lsa_typename(lsa_type),
                otype,
            )
            del self.opaque_change_cb[(lsa_type, otype)]

        await self._register_opaque_data(lsa_type, otype)

    async def wait_opaque_ready(self, lsa_type, otype):
        async with self.ready_lock:
            cond = self.ready_cond[lsa_type].get(otype)
            if cond is True:
                return

            assert self.wait_ready

            logging.debug(
                "waiting for ready %s opaque-type %s", lsa_typename(lsa_type), otype
            )

            if not cond:
                cond = self.ready_cond[lsa_type][otype] = []

            evt = Event()
            cond.append(evt)

        await evt.wait()
        logging.debug("READY for %s opaque-type %s", lsa_typename(lsa_type), otype)

    async def register_opaque_data_wait(self, lsa_type, otype, callback=None):
        """Register intent to advertise opaque data and wait for ready.

        The API currently only allows a single "owner" of each unique (lsa_type,otype).

        Args:
            lsa_type: LSA_TYPE_OPAQUE_{LINK,AREA,AS}
            otype: (octet) opaque type.
            callback: if given, callback will be called when changes are received for
                LSA of the given (lsa_type, otype). The callbacks signature is:

                `callback(msg_type, ifaddr, area_id, lsa_header, data, lsa)`

                Args:
                    msg_type: MSG_LSA_UPDATE_NOTIFY or MSG_LSA_DELETE_NOTIFY
                    ifaddr: integer identifying an interface (by IP address)
                    area_id: integer identifying an area
                    lsa_header: the LSA header as an unpacked tuple (fmt: ">HBBIILHH")
                    data: the opaque data that follows the LSA header
                    lsa: the octets of the full lsa
        Raises:

            See `msg_send_raises`
        """
        await self.register_opaque_data(lsa_type, otype, callback)
        await self.wait_opaque_ready(lsa_type, otype)

    async def unregister_opaque_data(self, lsa_type, otype):
        """Unregister intent to advertise opaque data.

        This will also cause the server to flush/delete all opaque data of
        the given (lsa_type,otype).

        Args:
            lsa_type: LSA_TYPE_OPAQUE_{LINK,AREA,AS}
            otype: (octet) opaque type.
        Raises:
            See `msg_send_raises`
        """
        assert await self.is_registered(
            lsa_type, otype
        ), "Unregistering unregistered type"

        if (lsa_type, otype) in self.opaque_change_cb:
            del self.opaque_change_cb[(lsa_type, otype)]

        mt = MSG_UNREGISTER_OPAQUETYPE
        mp = struct.pack(msg_fmt[mt], lsa_type, otype)
        await self.msg_send_raises(mt, mp)

    async def monitor_lsa(self, callback=None):
        """Monitor changes to LSAs.

        Args:
            callback: if given, callback will be called when changes are received for
                any LSA. The callback signature is:

                `callback(msg_type, ifaddr, area_id, lsa_header, extra, lsa)`

                Args:
                    msg_type: MSG_LSA_UPDATE_NOTIFY or MSG_LSA_DELETE_NOTIFY
                    ifaddr: integer identifying an interface (by IP address)
                    area_id: integer identifying an area
                    lsa_header: the LSA header as an unpacked tuple (fmt: ">HBBIILHH")
                    extra: the octets that follow the LSA header
                    lsa: the octets of the full lsa
        """
        self.lsa_change_cb = callback
        await self.req_lsdb_sync()

    async def monitor_reachable(self, callback=None):
        """Monitor the set of reachable routers.

        The property `reachable_routers` contains the set() of reachable router IDs
        as integers. This set is updated prior to calling the `callback`

        Args:
            callback: callback will be called when the set of reachable
                routers changes. The callback signature is:

                `callback(added, removed)`

                Args:
                    added: list of integer router IDs being added
                    removed: list of integer router IDs being removed
        """
        self.reachable_change_cb = callback
        await self.req_reachable_routers()

    async def monitor_ism(self, callback=None):
        """Monitor the state of OSPF enabled interfaces.

        Args:
            callback: callback will be called when an interface changes state.
                The callback signature is:

                `callback(ifaddr, area_id, state)`

                Args:
                    ifaddr: integer identifying an interface (by IP address)
                    area_id: integer identifying an area
                    state: ISM_*
        """
        self.ism_change_cb = callback
        await self.req_ism_states()

    async def monitor_nsm(self, callback=None):
        """Monitor the state of OSPF neighbors.

        Args:
            callback: callback will be called when a neighbor changes state.
                The callback signature is:

                `callback(ifaddr, nbr_addr, router_id, state)`

                Args:
                    ifaddr: integer identifying an interface (by IP address)
                    nbr_addr: integer identifying neighbor by IP address
                    router_id: integer identifying neighbor router ID
                    state: NSM_*
        """
        self.nsm_change_cb = callback
        await self.req_nsm_states()

    async def monitor_router_id(self, callback=None):
        """Monitor the OSPF router ID.

        The property `router_id` contains the OSPF urouter ID.
        This value is updated prior to calling the `callback`

        Args:
            callback: callback will be called when the router ID changes.
                The callback signature is:

                `callback(new_router_id, old_router_id)`

                Args:
                    new_router_id: the new router ID
                    old_router_id: the old router ID
        """
        self.router_id_change_cb = callback
        await self.req_router_id_sync()


# ================
# CLI/Script Usage
# ================
def next_action(action_list=None):
    "Get next action from list or STDIN"
    if action_list:
        for action in action_list:
            yield action
    else:
        while True:
            action = input("")
            if not action:
                break
            yield action.strip()


async def async_main(args):
    c = OspfOpaqueClient(args.server)
    await c.connect()

    try:
        # Start handling async messages from server.
        if sys.version_info[1] > 6:
            asyncio.create_task(c._handle_msg_loop())
        else:
            asyncio.get_event_loop().create_task(c._handle_msg_loop())

        await c.req_lsdb_sync()
        await c.req_reachable_routers()
        await c.req_ism_states()
        await c.req_nsm_states()

        for action in next_action(args.actions):
            _s = action.split(",")
            what = _s.pop(False)
            if what.casefold() == "wait":
                stime = int(_s.pop(False))
                logging.info("waiting %s seconds", stime)
                await asyncio.sleep(stime)
                logging.info("wait complete: %s seconds", stime)
                continue
            ltype = int(_s.pop(False))
            if ltype == 11:
                addr = ip(0)
            else:
                aval = _s.pop(False)
                try:
                    addr = ip(int(aval))
                except ValueError:
                    addr = ip(aval)
            oargs = [addr, ltype, int(_s.pop(False)), int(_s.pop(False))]

            if not await c.is_registered(oargs[1], oargs[2]):
                await c.register_opaque_data_wait(oargs[1], oargs[2])

            if what.casefold() == "add":
                try:
                    b = bytes.fromhex(_s.pop(False))
                except IndexError:
                    b = b""
                logging.info("opaque data is %s octets", len(b))
                # Needs to be multiple of 4 in length
                mod = len(b) % 4
                if mod:
                    b += b"\x00" * (4 - mod)
                    logging.info("opaque padding to %s octets", len(b))

                await c.add_opaque_data(*oargs, b)
            else:
                assert what.casefold().startswith("del")
                f = 0
                if len(_s) >= 1:
                    try:
                        f = int(_s.pop(False))
                    except IndexError:
                        f = 0
                await c.delete_opaque_data(*oargs, f)
        if not args.actions or args.exit:
            return 0
    except Exception as error:
        logging.error("async_main: unexpected error: %s", error, exc_info=True)
        return 2

    try:
        logging.info("Sleeping forever")
        while True:
            await asyncio.sleep(120)
    except EOFError:
        logging.info("Got EOF from OSPF API server on async notify socket")
        return 2


def main(*args):
    ap = argparse.ArgumentParser(args)
    ap.add_argument("--logtag", default="CLIENT", help="tag to identify log messages")
    ap.add_argument("--exit", action="store_true", help="Exit after commands")
    ap.add_argument("--server", default="localhost", help="OSPF API server")
    ap.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    ap.add_argument(
        "actions",
        nargs="*",
        help="WAIT,SEC|(ADD|DEL),LSATYPE,[ADDR,],OTYPE,OID,[HEXDATA|DEL_FLAG]",
    )
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: {}: %(name)s %(message)s".format(
            args.logtag
        ),
    )

    logging.info("ospfclient: starting")

    status = 3
    try:
        if sys.version_info[1] > 6:
            # python >= 3.7
            status = asyncio.run(async_main(args))
        else:
            loop = asyncio.get_event_loop()
            try:
                status = loop.run_until_complete(async_main(args))
            finally:
                loop.close()
    except KeyboardInterrupt:
        logging.info("Exiting, received KeyboardInterrupt in main")
    except Exception as error:
        logging.info("Exiting, unexpected exception %s", error, exc_info=True)
    else:
        logging.info("ospfclient: clean exit")

    return status


if __name__ == "__main__":
    exit_status = main()
    sys.exit(exit_status)
