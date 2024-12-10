#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: MIT
#
# February 22 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.

import argparse
import logging
import os
import sys
<<<<<<< HEAD
=======
import tempfile
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))

<<<<<<< HEAD
# This is painful but works if you have installed grpc and grpc_tools would be *way*
# better if we actually built and installed these but ... python packaging.
try:
    import grpc
    import grpc_tools

    sys.path.append(os.path.dirname(CWD))
    from munet.base import commander

    commander.cmd_raises(f"cp {CWD}/../../../grpc/frr-northbound.proto .")
    commander.cmd_raises(
        f"python -m grpc_tools.protoc --python_out=. --grpc_python_out=. -I . frr-northbound.proto"
    )
except Exception as error:
    logging.error("can't create proto definition modules %s", error)
    raise

try:
    sys.path[0:0] = "."
    import frr_northbound_pb2
    import frr_northbound_pb2_grpc

    # Would be nice if compiling the modules internally from the source worked
    # # import grpc_tools.protoc
    # # proto_include = pkg_resources.resource_filename("grpc_tools", "_proto")
    # from grpc_tools.protoc import _proto_file_to_module_name, _protos_and_services
    # try:
    #     frr_northbound_pb2, frr_northbound_pb2_grpc = _protos_and_services(
    #         "frr_northbound.proto"
    #     )
    # finally:
    #     os.chdir(CWD)
except Exception as error:
    logging.error("can't import proto definition modules %s", error)
    raise
=======
try:
    # Make sure we don't run-into ourselves in parallel operating environment
    tmpdir = tempfile.mkdtemp(prefix="grpc-client-")

    # This is painful but works if you have installed grpc and grpc_tools would be *way*
    # better if we actually built and installed these but ... python packaging.
    try:
        import grpc_tools
        from munet.base import commander

        import grpc

        commander.cmd_raises(f"cp {CWD}/../../../grpc/frr-northbound.proto .")
        commander.cmd_raises(
            "python3 -m grpc_tools.protoc"
            f" --python_out={tmpdir} --grpc_python_out={tmpdir}"
            f" -I {CWD}/../../../grpc frr-northbound.proto"
        )
    except Exception as error:
        logging.error("can't create proto definition modules %s", error)
        raise

    try:
        sys.path[0:0] = [tmpdir]
        import frr_northbound_pb2
        import frr_northbound_pb2_grpc

        sys.path = sys.path[1:]
    except Exception as error:
        logging.error("can't import proto definition modules %s", error)
        raise
finally:
    commander.cmd_nostatus(f"rm -rf {tmpdir}")
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)


class GRPCClient:
    def __init__(self, server, port):
        self.channel = grpc.insecure_channel("{}:{}".format(server, port))
        self.stub = frr_northbound_pb2_grpc.NorthboundStub(self.channel)

    def get_capabilities(self):
        request = frr_northbound_pb2.GetCapabilitiesRequest()
        response = "NONE"
        try:
            response = self.stub.GetCapabilities(request)
        except Exception as error:
            logging.error("Got exception from stub: %s", error)

        logging.debug("GRPC Capabilities: %s", response)
        return response

<<<<<<< HEAD
    def get(self, xpath):
        request = frr_northbound_pb2.GetRequest()
        request.path.append(xpath)
        request.type = frr_northbound_pb2.GetRequest.ALL
        request.encoding = frr_northbound_pb2.XML
        xml = ""
        for r in self.stub.Get(request):
            logging.info('GRPC Get path: "%s" value: %s', request.path, r)
            xml += str(r.data.data)
        return xml
=======
    def get(self, xpath, encoding, gtype):
        request = frr_northbound_pb2.GetRequest()
        request.path.append(xpath)
        request.type = gtype
        request.encoding = encoding
        result = ""
        for r in self.stub.Get(request):
            logging.debug('GRPC Get path: "%s" value: %s', request.path, r)
            result += str(r.data.data)
        return result
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)


def next_action(action_list=None):
    "Get next action from list or STDIN"
    if action_list:
        for action in action_list:
            yield action
    else:
        while True:
            try:
                action = input("")
                if not action:
                    break
                yield action.strip()
            except EOFError:
                break


def main(*args):
    parser = argparse.ArgumentParser(description="gRPC Client")
    parser.add_argument(
        "-s", "--server", default="localhost", help="gRPC Server Address"
    )
    parser.add_argument(
        "-p", "--port", type=int, default=50051, help="gRPC Server TCP Port"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    parser.add_argument("--check", action="store_true", help="check runable")
<<<<<<< HEAD
=======
    parser.add_argument("--xml", action="store_true", help="encode XML instead of JSON")
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    parser.add_argument("actions", nargs="*", help="GETCAP|GET,xpath")
    args = parser.parse_args(*args)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: GRPC-CLI-CLIENT: %(name)s %(message)s",
    )

    if args.check:
        sys.exit(0)

<<<<<<< HEAD
=======
    encoding = frr_northbound_pb2.XML if args.xml else frr_northbound_pb2.JSON

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
    c = GRPCClient(args.server, args.port)

    for action in next_action(args.actions):
        action = action.casefold()
<<<<<<< HEAD
        logging.info("GOT ACTION: %s", action)
        if action == "getcap":
            caps = c.get_capabilities()
            print("Capabilities:", caps)
        elif action.startswith("get,"):
            # Print Interface State and Config
            _, xpath = action.split(",", 1)
            print("Get XPath: ", xpath)
            xml = c.get(xpath)
            print("{}: {}".format(xpath, xml))
=======
        logging.debug("GOT ACTION: %s", action)
        if action == "getcap":
            caps = c.get_capabilities()
            print(caps)
        elif action.startswith("get,"):
            # Get and print config and state
            _, xpath = action.split(",", 1)
            logging.debug("Get XPath: %s", xpath)
            print(c.get(xpath, encoding, gtype=frr_northbound_pb2.GetRequest.ALL))
        elif action.startswith("get-config,"):
            # Get and print config
            _, xpath = action.split(",", 1)
            logging.debug("Get Config XPath: %s", xpath)
            print(c.get(xpath, encoding, gtype=frr_northbound_pb2.GetRequest.CONFIG))
            # for _ in range(0, 1):
        elif action.startswith("get-state,"):
            # Get and print state
            _, xpath = action.split(",", 1)
            logging.debug("Get State XPath: %s", xpath)
            print(c.get(xpath, encoding, gtype=frr_northbound_pb2.GetRequest.STATE))
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
            # for _ in range(0, 1):


if __name__ == "__main__":
    main()
