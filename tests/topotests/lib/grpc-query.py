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

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))

# This is painful but works if you have installed grpc and grpc_tools would be *way*
# better if we actually built and installed these but ... python packaging.
try:
    import grpc
    import grpc_tools

    sys.path.append(os.path.dirname(CWD))
    from munet.base import commander

    commander.cmd_raises(f"cp {CWD}/../../../grpc/frr-northbound.proto .")
    commander.cmd_raises(
        f"python3 -m grpc_tools.protoc --python_out=. --grpc_python_out=. -I . frr-northbound.proto"
    )
except Exception as error:
    logging.error("can't create proto definition modules %s", error)
    raise

try:
    sys.path[0:0] = "."
    import frr_northbound_pb2
    import frr_northbound_pb2_grpc
except Exception as error:
    logging.error("can't import proto definition modules %s", error)
    raise


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
    parser.add_argument("actions", nargs="*", help="GETCAP|GET,xpath")
    args = parser.parse_args(*args)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: GRPC-CLI-CLIENT: %(name)s %(message)s",
    )

    if args.check:
        sys.exit(0)

    c = GRPCClient(args.server, args.port)

    for action in next_action(args.actions):
        action = action.casefold()
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
            # for _ in range(0, 1):


if __name__ == "__main__":
    main()
