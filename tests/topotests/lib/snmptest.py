# SPDX-License-Identifier: ISC
#
# topogen.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#
#

"""
SNMP library to test snmp walks and gets

Basic usage instructions:

* define an SnmpTester class giving a router, address, community and version
* use test_oid or test_walk to check values in MIBS
* see tests/topotest/simple-snmp-test/test_simple_snmp.py for example
"""

from lib.topolog import logger
import re


class SnmpTester(object):
    "A helper class for testing SNMP"

    def __init__(self, router, iface, community, version, options=""):
        self.community = community
        self.version = version
        self.router = router
        self.iface = iface
        self.options = options
        logger.info(
            "created SNMP tester: SNMPv{0} community:{1}".format(
                self.version, self.community
            )
        )

    def _snmp_config(self):
        """
        Helper function to build a string with SNMP
        configuration for commands.
        """
        return "-v {0} -c {1} {2} {3}".format(
            self.version, self.community, self.options, self.iface
        )

    @staticmethod
    def _get_snmp_value(snmp_output):
        tokens = snmp_output.strip().split()

        num_value_tokens = len(tokens) - 3

        # this copes with the emptys string return
        if num_value_tokens == 0:
            return tokens[2]

        if num_value_tokens > 1:
            output = ""
            index = 3
            while index < len(tokens) - 1:
                output += "{} ".format(tokens[index])
                index += 1
            output += "{}".format(tokens[index])
            return output
        # third token is the value of the object
        return tokens[3]

    @staticmethod
    def _get_snmp_oid(snmp_output):
        tokens = snmp_output.strip().split()

        # third token onwards is the value of the object
        return tokens[0].split(".", 1)[1]

    def _parse_multiline(self, snmp_output):
        results = snmp_output.strip().split("\n")

        out_dict = {}
        out_list = []
        for response in results:
            out_dict[self._get_snmp_oid(response)] = self._get_snmp_value(response)
            out_list.append(self._get_snmp_value(response))

        return out_dict, out_list

    def get(self, oid):
        cmd = "snmpget {0} {1} 2>&1 | grep -v SNMPv2-PDU".format(
            self._snmp_config(), oid
        )
        result = self.router.cmd(cmd)
        if "not found" in result:
            return None
        return self._get_snmp_value(result)

    def get_next(self, oid):
        cmd = "snmpgetnext {0} {1} 2>&1 | grep -v SNMPv2-PDU".format(
            self._snmp_config(), oid
        )

        result = self.router.cmd(cmd)
        print("get_next: {}".format(result))
        if "not found" in result:
            return None
        return self._get_snmp_value(result)

    def walk(self, oid):
        cmd = "snmpwalk {0} {1} 2>&1 | grep -v SNMPv2-PDU".format(
            self._snmp_config(), oid
        )

        result = self.router.cmd(cmd)
        return self._parse_multiline(result)

    def parse_notif_ipv4(self, notif):
        # normalise values
        notif = re.sub(":", "", notif)
        notif = re.sub('"([0-9]{2}) ([0-9]{2}) "', r"\1\2", notif)
        notif = re.sub('"([0-9]{2}) "', r"\1", notif)
        elems = re.findall(r"([0-9,\.]+) = ([0-9,\.]+)", notif)

        # remove common part
        elems = elems[1:]
        return elems

    def is_notif_bgp4_valid(self, output_list, address):
        oid_notif_type = ".1.3.6.1.6.3.1.1.4.1.0"
        peer_notif_established = ".1.3.6.1.2.1.15.0.1"
        peer_notif_backward = ".1.3.6.1.2.1.15.0.2"
        oid_peer_last_error = ".1.3.6.1.2.1.15.3.1.14"
        oid_peer_remote_addr = ".1.3.6.1.2.1.15.3.1.7"
        oid_peer_state = ".1.3.6.1.2.1.15.3.1.2"

        nb_notif = len(output_list)
        for nb in range(0, nb_notif - 1):
            # identify type of notification
            # established or BackwardTransition

            if output_list[nb][0][0] != "{}".format(oid_notif_type):
                return False

            if output_list[nb][0][1] == "{}".format(peer_notif_established):
                logger.info("Established notification")
            elif output_list[nb][0][1] == "{}".format(peer_notif_backward):
                logger.info("Backward transition notification")
            else:
                return False

            # same behavior for 2 notification type in bgp4
            if output_list[nb][1][0] != "{}.{}".format(oid_peer_remote_addr, address):
                return False

            if output_list[nb][2][0] != "{}.{}".format(oid_peer_last_error, address):
                return False
            if output_list[nb][3][0] != "{}.{}".format(oid_peer_state, address):
                return False

        return True

    def is_notif_bgp4v2_valid(self, output_list, address, type_requested):
        oid_notif_type = ".1.3.6.1.6.3.1.1.4.1.0"
        peer_notif_established = ".1.3.6.1.3.5.1.0.1"
        peer_notif_backward = ".1.3.6.1.3.5.1.0.2"
        oid_peer_state = ".1.3.6.1.3.5.1.1.2.1.13"
        oid_peer_local_port = ".1.3.6.1.3.5.1.1.2.1.6"
        oid_peer_remote_port = ".1.3.6.1.3.5.1.1.2.1.9"
        oid_peer_err_code_recv = ".1.3.6.1.3.5.1.1.3.1.1"
        oid_peer_err_sub_code_recv = ".1.3.6.1.3.5.1.1.3.1.2"
        oid_peer_err_recv_text = ".1.3.6.1.3.5.1.1.3.1.4"

        nb_notif = len(output_list)
        for nb in range(nb_notif):
            if output_list[nb][0][0] != "{}".format(oid_notif_type):
                return False

            if output_list[nb][0][1] == "{}".format(peer_notif_established):
                logger.info("Established notification")
                notif_type = "Estab"

            elif output_list[nb][0][1] == "{}".format(peer_notif_backward):
                logger.info("Backward transition notification")
                notif_type = "Backward"
            else:
                return False

            if notif_type != type_requested:
                continue

            if output_list[nb][1][0] != "{}.1.{}".format(oid_peer_state, address):
                continue

            if output_list[nb][2][0] != "{}.1.{}".format(oid_peer_local_port, address):
                return False

            if output_list[nb][3][0] != "{}.1.{}".format(oid_peer_remote_port, address):
                return False

            if notif_type == "Estab":
                return True

            if output_list[nb][4][0] != "{}.1.{}".format(
                oid_peer_err_code_recv, address
            ):
                return False

            if output_list[nb][5][0] != "{}.1.{}".format(
                oid_peer_err_sub_code_recv, address
            ):
                return False

            if output_list[nb][6][0] != "{}.1.{}".format(
                oid_peer_err_recv_text, address
            ):
                return False

            return True

        return False

    def get_notif_bgp4(self, output_file):
        notifs = []
        notif_list = []
        whitecleanfile = re.sub("\t", " ", output_file)
        results = whitecleanfile.strip().split("\n")

        # don't consider additional SNMP or application messages
        for result in results:
            if re.search(r"(\.([0-9]+))+\s", result):
                notifs.append(result)

        oid_v4 = r"1\.3\.6\.1\.2\.1\.15"
        for one_notif in notifs:
            is_ipv4_notif = re.search(oid_v4, one_notif)
            if is_ipv4_notif != None:
                formated_notif = self.parse_notif_ipv4(one_notif)
                notif_list.append(formated_notif)

        return notif_list

    def get_notif_bgp4v2(self, output_file):
        notifs = []
        notif_list = []
        whitecleanfile = re.sub("\t", " ", output_file)
        results = whitecleanfile.strip().split("\n")

        # don't consider additional SNMP or application messages
        for result in results:
            if re.search(r"(\.([0-9]+))+\s", result):
                notifs.append(result)

        oid_v6 = r"1\.3\.6\.1\.3\.5\.1"
        for one_notif in notifs:
            is_ipv6_notif = re.search(oid_v6, one_notif)
            if is_ipv6_notif != None:
                formated_notif = self.parse_notif_ipv4(one_notif)
                notif_list.append(formated_notif)

        return notif_list

    def test_oid(self, oid, value):
        print("oid: {}".format(self.get_next(oid)))
        return self.get_next(oid) == value

    def test_oid_walk(self, oid, values, oids=None):
        results_dict, results_list = self.walk(oid)
        print("test_oid_walk: {} {}".format(oid, results_dict))
        if oids is not None:
            index = 0
            for oid in oids:
                # avoid key error for missing keys
                if not oid in results_dict.keys():
                    print("FAIL: missing oid key {}".format(oid))
                    return False
                if results_dict[oid] != values[index]:
                    print(
                        "FAIL{} {} |{}| == |{}|".format(
                            oid, index, results_dict[oid], values[index]
                        )
                    )
                    return False
                index += 1
            return True

        # Return true if 'values' is a subset of 'results_list'
        print("test {} == {}".format(results_list[: len(values)], values))
        return results_list[: len(values)] == values
