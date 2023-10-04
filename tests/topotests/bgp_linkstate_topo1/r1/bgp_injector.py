#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

#
# Copyright 2018 Jorge Borreicho
# Copyright 2023 6WIND S.A.

"""
    BGP prefix injection tool
"""

import socket
import sys
import time
from datetime import datetime
import struct
import threading
import json
import os
import re
import signal
import errno


AFI_IPV4 = 1
SAFI_UNICAST = 1

AFI_LINKSTATE = 16388
SAFI_LINKSTATE = 71

saved_pid = False
global pid_file

class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def writelines(self, datas):
       self.stream.writelines(datas)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

def keepalive_thread(conn, interval):

    # infinite loop so that function do not terminate and thread do not end.
    while True:
        time.sleep(interval)
        keepalive_bgp(conn)


def receive_thread(conn):

    # infinite loop so that function do not terminate and thread do not end.
    while True:

        # Receiving from client
        r = conn.recv(1500)
        while True:
            start_ptr = (
                r.find(
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                )
                + 16
            )
            end_ptr = (
                r[16:].find(
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
                )
                + 16
            )
            if (
                start_ptr >= end_ptr
            ):  # a single message was sent in the BGP packet OR it is the last message of the BGP packet
                decode_bgp(r[start_ptr:])
                break
            else:  # more messages left to decode
                decode_bgp(r[start_ptr:end_ptr])
                r = r[end_ptr:]


def decode_bgp(msg):
    if len(msg) < 3:
        return
    msg_length, msg_type = struct.unpack("!HB", msg[0:3])
    if msg_type == 4:
        # print(timestamp + " - " + "Received KEEPALIVE") #uncomment to debug
        pass
    elif msg_type == 2:
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "Received UPDATE")
    elif msg_type == 1:
        version, remote_as, holdtime, i1, i2, i3, i4, opt_length = struct.unpack(
            "!BHHBBBBB", msg[3:13]
        )
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "Received OPEN")
        print()
        print(
            "--> Version:"
            + str(version)
            + ", Remote AS: "
            + str(remote_as)
            + ", Hold Time:"
            + str(holdtime)
            + ", Remote ID: "
            + str(i1)
            + "."
            + str(i2)
            + "."
            + str(i3)
            + "."
            + str(i4)
        )
        print()
    elif msg_type == 3:
        timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        print(timestamp + " - " + "Received NOTIFICATION")


def multiprotocol_capability(afi, safi):
    hexstream = bytes.fromhex("02060104")
    hexstream += struct.pack("!H", afi)
    hexstream += struct.pack("!B", 0)
    hexstream += struct.pack("!B", safi)

    return hexstream


def open_bgp(conn, config):

    # Build the BGP Message
    bgp_version = b"\x04"
    bgp_as = struct.pack("!H", config["my_as"])
    bgp_hold_time = struct.pack("!H", config["hold_time"])

    octet = config["bgp_identifier"].split(".")
    bgp_identifier = struct.pack(
        "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
    )

    bgp_opt = b""
    bgp_opt += multiprotocol_capability(AFI_IPV4, SAFI_UNICAST)
    bgp_opt += multiprotocol_capability(AFI_LINKSTATE, SAFI_LINKSTATE)

    bgp_opt_lenght = struct.pack("!B", len(bgp_opt))

    bgp_message = (
        bgp_version + bgp_as + bgp_hold_time + bgp_identifier + bgp_opt_lenght + bgp_opt
    )

    # Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1
    bgp_marker = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x01"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header + bgp_message

    conn.send(bgp_packet)
    return 0


def keepalive_bgp(conn):

    # Build the BGP Header
    total_length = 16 + 2 + 1
    bgp_marker = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x04"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header

    conn.send(bgp_packet)
    return 0


def encode_ipv4_prefix(address, netmask):

    octet = address.split(".")
    length = struct.pack("!B", int(netmask))

    if int(netmask) <= 8:
        prefix = struct.pack("!B", int(octet[0]))
    elif int(netmask) <= 16:
        prefix = struct.pack("!BB", int(octet[0]), int(octet[1]))
    elif int(netmask) <= 24:
        prefix = struct.pack("!BBB", int(octet[0]), int(octet[1]), int(octet[2]))
    else:
        prefix = struct.pack(
            "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
        )

    return length + prefix


def encode_path_attribute_mp_reach_nrli(afi, safi, data, config):
    hexstream = b""
    hexstream += b"\x90"  # flags optional, extended
    hexstream += struct.pack("!B", 14)  # type code MP_REACH_NLRI

    hexstream2 = b""
    hexstream2 += struct.pack("!H", afi)
    hexstream2 += struct.pack("!B", safi)
    hexstream2 += struct.pack("!B", 4)  # nexthop length
    hexstream2 += socket.inet_aton(config["local_address"])  # nexthop IPv4
    hexstream2 += b"\x00"  # SNPA
    hexstream2 += data

    hexstream += struct.pack("!H", len(hexstream2))  # length
    hexstream += hexstream2

    return hexstream


def encode_path_attribute_linkstate(data):
    hexstream = b""
    hexstream += b"\x80"  # flags optional
    hexstream += struct.pack("!B", 29)  # type code BGP-LS
    hexstream += struct.pack("!B", len(data))  # length
    hexstream += data

    return hexstream


def encode_path_attribute(type, value):

    path_attributes = {
        "origin": [b"\x40", 1],
        "as-path": [b"\x40", 2],
        "next-hop": [b"\x40", 3],
        "med": [b"\x80", 4],
        "local_pref": [b"\x40", 5],
        "communities": [b"\xc0", 8],
    }

    attribute_flag = path_attributes[type][0]
    attribute_type_code = struct.pack("!B", int(path_attributes[type][1]))

    if type == "origin":
        attribute_value = struct.pack("!B", value)
    elif type == "as-path":
        as_number_list = value.split(" ")
        attribute_value = struct.pack("!BB", 2, len(as_number_list))
        for as_number in as_number_list:
            attribute_value += struct.pack("!H", int(as_number))
    elif type == "next-hop":
        octet = value.split(".")
        attribute_value = struct.pack(
            "!BBBB", int(octet[0]), int(octet[1]), int(octet[2]), int(octet[3])
        )
    elif type == "med":
        attribute_value = struct.pack("!I", value)
    elif type == "local_pref":
        attribute_value = struct.pack("!I", value)
    elif type == "communities":
        communities_list = value.split(" ")
        attribute_value = b""
        for community in communities_list:
            aux = community.split(":")
            attribute_value += struct.pack("!HH", int(aux[0]), int(aux[1]))

    attribute_length = struct.pack("!B", len(attribute_value))

    return attribute_flag + attribute_type_code + attribute_length + attribute_value


def encode_tlvs(tlvs):
    stream = b""
    for key, tlv_data in tlvs.items():
        if isinstance(key, str) and key.isdigit():
            tlv_type = int(key)
        else:
            # key is not a TLV
            continue
        if isinstance(tlv_data, str):
            if tlv_type != 0:
                # TLV type 0 is fake TLV
                stream += struct.pack("!H", tlv_type)
                stream += struct.pack("!H", len(bytes.fromhex(tlv_data)))
            stream += bytes.fromhex(tlv_data)
        elif isinstance(tlv_data, dict):
            # TLV contains sub-TLV
            stream += struct.pack("!H", tlv_type)

            stream_subtlv = encode_tlvs(tlv_data)
            stream += struct.pack("!H", len(stream_subtlv))
            stream += stream_subtlv
        else:
            # invalid input
            assert 0

    return stream


def encode_linkstate_nrli_tlv(nlri):
    stream = b""
    stream += bytes.fromhex(nlri["type"])

    stream2 = b""
    stream2 += bytes.fromhex(nlri["proto"])
    stream2 += bytes.fromhex(nlri["id"])
    stream2 += encode_tlvs(nlri)

    stream += struct.pack("!H", len(stream2))
    stream += stream2

    return stream


def update_bgp(conn, link_state, config):

    # Build the BGP Message

    # Expired Routes
    # 1 - Withdrawn Routes

    bgp_withdrawn_routes = b""
    max_length_reached = False

    bgp_withdrawn_routes_length = struct.pack("!H", len(bgp_withdrawn_routes))
    bgp_withdrawn_routes = bgp_withdrawn_routes_length + bgp_withdrawn_routes

    # New Routes
    # 2 - Path Attributes

    path_attributes = config["path_attributes"]
    bgp_mss = config["mss"]

    bgp_total_path_attributes = b""

    # encode link-state MP_REACH NLRI
    data = encode_linkstate_nrli_tlv(link_state["nlri"])
    bgp_total_path_attributes += encode_path_attribute_mp_reach_nrli(
        AFI_LINKSTATE, SAFI_LINKSTATE, data, config
    )

    # encode classic attributes
    for key in path_attributes.keys():
        bgp_total_path_attributes += encode_path_attribute(key, path_attributes[key])

    # encode link-state attributes
    if "attr" in link_state:
        data = encode_tlvs(link_state["attr"])
    else:
        data = b""
    bgp_total_path_attributes += encode_path_attribute_linkstate(data)

    bgp_total_path_attributes_length = struct.pack("!H", len(bgp_total_path_attributes))
    bgp_total_path_attributes = (
        bgp_total_path_attributes_length + bgp_total_path_attributes
    )

    # 3- Network Layer Reachability Information (NLRI)

    bgp_new_routes = b""

    bgp_message = bgp_withdrawn_routes + bgp_total_path_attributes + bgp_new_routes

    # Build the BGP Header
    total_length = len(bgp_message) + 16 + 2 + 1
    bgp_marker = b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    bgp_length = struct.pack("!H", total_length)
    bgp_type = b"\x02"
    bgp_header = bgp_marker + bgp_length + bgp_type

    bgp_packet = bgp_header + bgp_message

    conn.send(bgp_packet)

    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "Sent UPDATE")

    return 0


def str2ip(ip_str):
    s_octet = ip_str.split(".")
    ip_addr = struct.pack(
        "!BBBB", int(s_octet[0]), int(s_octet[1]), int(s_octet[2]), int(s_octet[3])
    )
    return ip_addr


def check_pid(pid):
    if pid < 0:  # user input error
        return False
    if pid == 0:  # all processes
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError as err:
        if err.errno == errno.EPERM:  # a process we were denied access to
            return True
        if err.errno == errno.ESRCH:  # No such process
            return False
        # should never happen
        return False


def savepid():
    ownid = os.getpid()

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    mode = ((os.R_OK | os.W_OK) << 6) | (os.R_OK << 3) | os.R_OK

    try:
        fd = os.open(pid_file, flags, mode)
    except OSError:
        try:
            pid = open(pid_file, "r").readline().strip()
            if check_pid(int(pid)):
                sys.stderr.write(
                    "PIDfile already exists and program still running %s\n" % pid_file
                )
                return False
            else:
                # If pid is not running, reopen file without O_EXCL
                fd = os.open(pid_file, flags ^ os.O_EXCL, mode)
        except (OSError, IOError, ValueError):
            sys.stderr.write(
                "issue accessing PID file %s (most likely permission or ownership)\n"
                % pid_file
            )
            return False

    try:
        f = os.fdopen(fd, "w")
        line = "%d\n" % ownid
        f.write(line)
        f.close()
        saved_pid = True
    except IOError:
        sys.stderr.write("Can not create PIDfile %s\n" % pid_file)
        return False
    print("Created PIDfile %s with value %d\n" % (pid_file, ownid))
    return True


def removepid():
    if not saved_pid:
        return
    try:
        os.remove(pid_file)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            pass
        else:
            sys.stderr.write("Can not remove PIDfile %s\n" % pid_file)
            return
    sys.stderr.write("Removed PIDfile %s\n" % pid_file)


def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            # Exit first parent
            sys.exit(0)
    except OSError as e:
        print("Fork #1 failed: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    # Decouple from parent environment
    os.chdir("/")
    os.setsid()
    os.umask(0)

    # Do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Exit from second parent
            sys.exit(0)
    except OSError as e:
        print("Fork #2 failed: %d (%s)" % (e.errno, e.strerror))
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(os.devnull, "r")
    so = open(os.devnull, "a+")
    se = open(os.devnull, "a+")

    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


def term(signal, frame):
    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "^C received, shutting down.\n")
    bgp_socket.close()
    removepid()
    exit()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # daemonize and log to file
        daemonize()
        pid_file = os.path.join(sys.argv[1], "bgp_injector.pid")
        savepid()
        # deal with daemon termination
        signal.signal(signal.SIGTERM, term)
        signal.signal(signal.SIGINT, term) # CTRL + C

        log_dir = os.path.join(sys.argv[1], "bgp_injector.log")
        f = open(log_dir, 'w')
        sys.stdout = Unbuffered(f)
        sys.stderr = Unbuffered(f)

    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "Starting BGP injector ")

    CONFIG_FILENAME = os.path.join(sys.path[0], "bgp_injector.cfg")

    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "Reading config file " + CONFIG_FILENAME)

    input_file = open(CONFIG_FILENAME, "r")

    input = input_file.read()
    # cleanup comments that are not supported by JSON
    json_input = re.sub(r"//.*\n", "", input, flags=re.MULTILINE)

    config = json.loads(json_input)

    bgp_peer = config["peer_address"]
    bgp_local = config["local_address"]
    bgp_mss = config["mss"]
    bgp_port = config["port"]
    rib = dict()
    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "Starting BGP... (peer: " + str(bgp_peer) + ")")

    retry = 30
    while retry:
        retry -= 1
        try:
            bgp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            bgp_socket.bind((bgp_local, 0))
            bgp_socket.connect((bgp_peer, bgp_port))
            open_bgp(bgp_socket, config)
            break
        except TimeoutError:
            if retry == 0:
                timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                print(timestamp + " - " + "Error: timeout connecting to the peer.")
                exit()
            time.sleep(1)
        except OSError as e:
            if retry == 0:
                timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                print(timestamp + " - " + "Error: cannot connect to the peer: " + str(e))
                exit()
            time.sleep(1)

    receive_worker = threading.Thread(
        target=receive_thread, args=(bgp_socket,)
    )  # wait from BGP msg from peer and process them
    receive_worker.setDaemon(True)
    receive_worker.start()

    keepalive_worker = threading.Thread(
        target=keepalive_thread,
        args=(
            bgp_socket,
            (config["hold_time"]) / 3,
        ),
    )  # send keep alives every 10s by default
    keepalive_worker.setDaemon(True)
    keepalive_worker.start()

    # send a first keepalive packet before sending the initial UPDATE packet
    keepalive_bgp(bgp_socket)

    timestamp = str(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print(timestamp + " - " + "BGP is up.")

    time.sleep(3)
    for link_state in config["link_states"]:
        update_bgp(
            bgp_socket,
            link_state,
            config,
        )

    while True:
        time.sleep(60)
