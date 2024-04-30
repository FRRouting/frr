#
# topogen.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
SNMP library to test snmp walks and gets

Basic usage instructions:

* define an SnmpTester class giving a router, address, community and version
* use test_oid or test_walk to check values in MIBS
* see tests/topotest/simple-snmp-test/test_simple_snmp.py for example
"""

from lib.topolog import logger


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

    @staticmethod
    def _get_snmp_oid(snmp_output):
        tokens = snmp_output.strip().split()

        #        if len(tokens) > 5:
        #            return None

        # third token is the value of the object
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
        cmd = "snmpget {0} {1}".format(self._snmp_config(), oid)

        result = self.router.cmd(cmd)
        if "not found" in result:
            return None
        return self._get_snmp_value(result)

    def get_next(self, oid):
        cmd = "snmpgetnext {0} {1}".format(self._snmp_config(), oid)

        result = self.router.cmd(cmd)
        print("get_next: {}".format(result))
        if "not found" in result:
            return None
        return self._get_snmp_value(result)

    def walk(self, oid):
        cmd = "snmpwalk {0} {1}".format(self._snmp_config(), oid)

        result = self.router.cmd(cmd)
        return self._parse_multiline(result)

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
