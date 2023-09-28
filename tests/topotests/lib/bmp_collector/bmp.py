# SPDX-License-Identifier: ISC

# Copyright 2023 6WIND S.A.
# Authored by Farid Mihoub <farid.mihoub@6wind.com>
#
"""
BMP main module:
    - dissect monitoring messages in the way to get updated/withdrawed prefixes
    - XXX: missing RFCs references
    - XXX: more bmp messages types to dissect
    - XXX: complete bgp message dissection
"""
import datetime
import ipaddress
import json
import os
import struct

from bgp.update import BGPUpdate
from bgp.update.rd import RouteDistinguisher


SEQ = 0
LOG_DIR = "/var/log/"
LOG_FILE = "/var/log/bmp.log"

IS_ADJ_RIB_OUT = 1 << 4
IS_AS_PATH = 1 << 5
IS_POST_POLICY = 1 << 6
IS_IPV6 = 1 << 7
IS_FILTERED = 1 << 7

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

def bin2str_ipaddress(ip_bytes, is_ipv6=False):
    if is_ipv6:
        return str(ipaddress.IPv6Address(ip_bytes))
    return str(ipaddress.IPv4Address(ip_bytes[-4:]))

def log2file(logs):
    """
    XXX: extract the useful information and save it in a flat dictionnary
    """
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(logs) + "\n")


#------------------------------------------------------------------------------
class BMPCodes:
    """
    XXX: complete the list, provide RFCs.
    """
    VERSION = 0x3

    BMP_MSG_TYPE_ROUTE_MONITORING = 0x00
    BMP_MSG_TYPE_STATISTICS_REPORT = 0x01
    BMP_MSG_TYPE_PEER_DOWN_NOTIFICATION =  0x02
    BMP_MSG_TYPE_PEER_UP_NOTIFICATION =  0x03
    BMP_MSG_TYPE_INITIATION = 0x04
    BMP_MSG_TYPE_TERMINATION = 0x05
    BMP_MSG_TYPE_ROUTE_MIRRORING = 0x06
    BMP_MSG_TYPE_ROUTE_POLICY = 0x64

    # initiation message types
    BMP_INIT_INFO_STRING = 0x00
    BMP_INIT_SYSTEM_DESCRIPTION = 0x01
    BMP_INIT_SYSTEM_NAME = 0x02
    BMP_INIT_VRF_TABLE_NAME = 0x03
    BMP_INIT_ADMIN_LABEL = 0x04

    # peer types
    BMP_PEER_GLOBAL_INSTANCE = 0x00
    BMP_PEER_RD_INSTANCE = 0x01
    BMP_PEER_LOCAL_INSTANCE = 0x02
    BMP_PEER_LOC_RIB_INSTANCE = 0x03

    # peer header flags
    BMP_PEER_FLAG_IPV6 = 0x80
    BMP_PEER_FLAG_POST_POLICY = 0x40
    BMP_PEER_FLAG_AS_PATH = 0x20
    BMP_PEER_FLAG_ADJ_RIB_OUT = 0x10

    # peer loc-rib flag
    BMP_PEER_FLAG_LOC_RIB = 0x80
    BMP_PEER_FLAG_LOC_RIB_RES = 0x7F

    # statistics type
    BMP_STAT_PREFIX_REJ = 0x00
    BMP_STAT_PREFIX_DUP = 0x01
    BMP_STAT_WITHDRAW_DUP = 0x02
    BMP_STAT_CLUSTER_LOOP = 0x03
    BMP_STAT_AS_LOOP = 0x04
    BMP_STAT_INV_ORIGINATOR = 0x05
    BMP_STAT_AS_CONFED_LOOP = 0x06
    BMP_STAT_ROUTES_ADJ_RIB_IN = 0x07
    BMP_STAT_ROUTES_LOC_RIB = 0x08
    BMP_STAT_ROUTES_PER_ADJ_RIB_IN = 0x09
    BMP_STAT_ROUTES_PER_LOC_RIB = 0x0A
    BMP_STAT_UPDATE_TREAT = 0x0B
    BMP_STAT_PREFIXES_TREAT = 0x0C
    BMP_STAT_DUPLICATE_UPDATE = 0x0D
    BMP_STAT_ROUTES_PRE_ADJ_RIB_OUT = 0x0E
    BMP_STAT_ROUTES_POST_ADJ_RIB_OUT = 0x0F
    BMP_STAT_ROUTES_PRE_PER_ADJ_RIB_OUT = 0x10
    BMP_STAT_ROUTES_POST_PER_ADJ_RIB_OUT = 0x11

    # peer down reason code
    BMP_PEER_DOWN_LOCAL_NOTIFY = 0x01
    BMP_PEER_DOWN_LOCAL_NO_NOTIFY = 0X02
    BMP_PEER_DOWN_REMOTE_NOTIFY = 0X03
    BMP_PEER_DOWN_REMOTE_NO_NOTIFY = 0X04
    BMP_PEER_DOWN_INFO_NO_LONGER = 0x05
    BMP_PEER_DOWN_SYSTEM_CLOSED = 0X06

    # termincation message types
    BMP_TERM_TYPE_STRING = 0x00
    BMP_TERM_TYPE_REASON = 0X01

    # termination reason code
    BMP_TERM_REASON_ADMIN_CLOSE = 0x00
    BMP_TERM_REASON_UNSPECIFIED = 0x01
    BMP_TERM_REASON_RESOURCES = 0x02
    BMP_TERM_REASON_REDUNDANT = 0x03
    BMP_TERM_REASON_PERM_CLOSE = 0x04

    # policy route tlv
    BMP_ROUTE_POLICY_TLV_VRF = 0x00
    BMP_ROUTE_POLICY_TLV_POLICY= 0x01
    BMP_ROUTE_POLICY_TLV_PRE_POLICY = 0x02
    BMP_ROUTE_POLICY_TLV_POST_POLICY = 0x03
    BMP_ROUTE_POLICY_TLV_STRING = 0x04


#------------------------------------------------------------------------------
class BMPMsg:
    """
    XXX: should we move register_msg_type and look_msg_type
    to generic Type class.
    """
    TYPES = {}
    UNKNOWN_TYPE = None
    HDR_STR = '!BIB'
    MIN_LEN = struct.calcsize(HDR_STR)
    TYPES_STR = {
        BMPCodes.BMP_MSG_TYPE_INITIATION: 'initiation',
        BMPCodes.BMP_MSG_TYPE_PEER_DOWN_NOTIFICATION: 'peer down notification',
        BMPCodes.BMP_MSG_TYPE_PEER_UP_NOTIFICATION: 'peer up notification',
        BMPCodes.BMP_MSG_TYPE_ROUTE_MONITORING: 'route monitoring',
        BMPCodes.BMP_MSG_TYPE_STATISTICS_REPORT: 'statistics report',
        BMPCodes.BMP_MSG_TYPE_TERMINATION: 'termination',
        BMPCodes.BMP_MSG_TYPE_ROUTE_MIRRORING: 'route mirroring',
        BMPCodes.BMP_MSG_TYPE_ROUTE_POLICY: 'route policy',
    }

    @classmethod
    def register_msg_type(cls, msgtype):
        def _register_type(subcls):
            cls.TYPES[msgtype] = subcls
            return subcls
        return _register_type

    @classmethod
    def lookup_msg_type(cls, msgtype):
        return cls.TYPES.get(msgtype, cls.UNKNOWN_TYPE)

    @classmethod
    def dissect_header(cls, data):
        """
        0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |    Version    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                        Message Length                         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        | Message Type  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        """
        if len(data) < cls.MIN_LEN:
            pass
        else:
            _version, _len, _type = struct.unpack(cls.HDR_STR, data[0:cls.MIN_LEN])
            return _version, _len, _type

    @classmethod
    def dissect(cls, data):
        global SEQ
        version, msglen, msgtype = cls.dissect_header(data)

        msg_data = data[cls.MIN_LEN:msglen]
        data = data[msglen:]

        if version != BMPCodes.VERSION:
            # XXX: log something
            return data

        msg_cls = cls.lookup_msg_type(msgtype)
        if msg_cls == cls.UNKNOWN_TYPE:
            # XXX: log something
            return data

        msg_cls.MSG_LEN = msglen - cls.MIN_LEN
        logs = msg_cls.dissect(msg_data)
        logs["seq"] = SEQ
        log2file(logs)
        SEQ += 1

        return data


#------------------------------------------------------------------------------
class BMPPerPeerMessage:
    """
    0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Peer Type   | Peer Flags    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                Peer Address (16 bytes)                        |
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                          Peer AS                              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Peer BGP ID                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Timestamp (seconds)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Timestamp (microseconds)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    PEER_UNPACK_STR = '!BB8s16sI4sII'
    PEER_TYPE_STR = {
        BMPCodes.BMP_PEER_GLOBAL_INSTANCE: 'global instance',
        BMPCodes.BMP_PEER_RD_INSTANCE: 'route distinguisher instance',
        BMPCodes.BMP_PEER_LOCAL_INSTANCE: 'local instance',
        BMPCodes.BMP_PEER_LOC_RIB_INSTANCE: 'loc-rib instance',
    }

    @classmethod
    def dissect(cls, data):
        (peer_type,
         peer_flags,
         peer_distinguisher,
         peer_address,
         peer_asn,
         peer_bgp_id,
         timestamp_secs,
         timestamp_microsecs) = struct.unpack_from(cls.PEER_UNPACK_STR, data)

        msg = {'peer_type': cls.PEER_TYPE_STR[peer_type]}

        if peer_type == 0x03:
            msg['is_filtered'] = bool(peer_flags & IS_FILTERED)
        else:
            # peer_flags = 0x0000 0000
            # ipv6, post-policy, as-path, adj-rib-out, reserverdx4
            is_adj_rib_out = bool(peer_flags & IS_ADJ_RIB_OUT)
            is_as_path = bool(peer_flags & IS_AS_PATH)
            is_post_policy = bool(peer_flags & IS_POST_POLICY)
            is_ipv6 = bool(peer_flags & IS_IPV6)
            msg['post_policy'] = is_post_policy
            msg['ipv6'] = is_ipv6
            msg['peer_ip'] = bin2str_ipaddress(peer_address, is_ipv6)


        peer_bgp_id = bin2str_ipaddress(peer_bgp_id)
        timestamp = float(timestamp_secs) + timestamp_microsecs * (10 ** -6)

        data = data[struct.calcsize(cls.PEER_UNPACK_STR):]
        msg.update({
            'peer_distinguisher': str(RouteDistinguisher(peer_distinguisher)),
            'peer_asn': peer_asn,
            'peer_bgp_id': peer_bgp_id,
            'timestamp': str(datetime.datetime.fromtimestamp(timestamp)),
        })

        return data, msg


#------------------------------------------------------------------------------
@BMPMsg.register_msg_type(BMPCodes.BMP_MSG_TYPE_ROUTE_MONITORING)
class BMPRouteMonitoring(BMPPerPeerMessage):

    @classmethod
    def dissect(cls, data):
        data, peer_msg = super().dissect(data)
        data, update_msg = BGPUpdate.dissect(data)
        return {**peer_msg, **update_msg}


#------------------------------------------------------------------------------
class BMPStatisticsReport:
    """
    0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Stats Count                            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |         Stat Type             |          Stat Len             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                        Stat Data                              |
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    pass


#------------------------------------------------------------------------------
class BMPPeerDownNotification:
    """
    0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Reason     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Data (present if Reason = 1, 2 or 3)               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    pass


#------------------------------------------------------------------------------
@BMPMsg.register_msg_type(BMPCodes.BMP_MSG_TYPE_PEER_UP_NOTIFICATION)
class BMPPeerUpNotification(BMPPerPeerMessage):
    """
    0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Local Address (16 bytes)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Local Port           |           Remote Port         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                    Sent OPEN Message                         #|
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                  Received OPEN Message                        |
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    UNPACK_STR = '!16sHH'
    MIN_LEN = struct.calcsize(UNPACK_STR)
    MSG_LEN = None

    @classmethod
    def dissect(cls, data):
        data, peer_msg = super().dissect(data)

        (local_addr,
         local_port,
         remote_port) = struct.unpack_from(cls.UNPACK_STR, data)

        msg = {
            **peer_msg,
            **{
                'local_ip': bin2str_ipaddress(local_addr, peer_msg.get('ipv6')),
                'local_port': int(local_port),
                'remote_port': int(remote_port),
            },
        }

        # XXX: dissect the bgp open message

        return msg


#------------------------------------------------------------------------------
@BMPMsg.register_msg_type(BMPCodes.BMP_MSG_TYPE_INITIATION)
class BMPInitiation:
    """
    0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |      Information Type         |        Information Length     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                   Information (variable)                      |
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    TLV_STR = '!HH'
    MIN_LEN = struct.calcsize(TLV_STR)
    FIELD_TO_STR = {
        BMPCodes.BMP_INIT_INFO_STRING: 'information',
        BMPCodes.BMP_INIT_ADMIN_LABEL: 'admin_label',
        BMPCodes.BMP_INIT_SYSTEM_DESCRIPTION: 'system_description',
        BMPCodes.BMP_INIT_SYSTEM_NAME: 'system_name',
        BMPCodes.BMP_INIT_VRF_TABLE_NAME: 'vrf_table_name',
    }

    @classmethod
    def dissect(cls, data):
        msg = {}
        while len(data) > cls.MIN_LEN:
            _type, _len = struct.unpack_from(cls.TLV_STR, data[0:cls.MIN_LEN])
            _value = data[cls.MIN_LEN: cls.MIN_LEN + _len].decode()

            msg[cls.FIELD_TO_STR[_type]] = _value
            data = data[cls.MIN_LEN + _len:]

        return msg


#------------------------------------------------------------------------------
class BMPTermination:
    """
    0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |          Information Type     |       Information Length      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Information (variable)                        |
    ~                                                               ~
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    """
    pass


#------------------------------------------------------------------------------
class BMPRouteMirroring:
    pass


#------------------------------------------------------------------------------
class BMPRoutePolicy:
    pass
