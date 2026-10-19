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
import tempfile

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
TOPOTESTS_DIR = os.path.dirname(CWD)
if TOPOTESTS_DIR not in sys.path:
    sys.path.insert(0, TOPOTESTS_DIR)

tmpdir = None
commander = None

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

        # Create health.proto for gRPC health check support
        health_proto = """
syntax = "proto3";

package grpc.health.v1;

message HealthCheckRequest {
  string service = 1;
}

message HealthCheckResponse {
  enum ServingStatus {
    UNKNOWN = 0;
    SERVING = 1;
    NOT_SERVING = 2;
    SERVICE_UNKNOWN = 3;
  }
  ServingStatus status = 1;
}

service Health {
  rpc Check(HealthCheckRequest) returns (HealthCheckResponse);
  rpc Watch(HealthCheckRequest) returns (stream HealthCheckResponse);
}
"""
        with open(os.path.join(tmpdir, "health.proto"), "w") as f:
            f.write(health_proto)
        commander.cmd_raises(
            "python3 -m grpc_tools.protoc"
            f" --python_out={tmpdir} --grpc_python_out={tmpdir}"
            f" -I {tmpdir} health.proto"
        )
    except Exception as error:
        logging.error("can't create proto definition modules %s", error)
        raise

    try:
        sys.path[0:0] = [tmpdir]
        import frr_northbound_pb2
        import frr_northbound_pb2_grpc
        import health_pb2
        import health_pb2_grpc

        sys.path = sys.path[1:]
    except Exception as error:
        logging.error("can't import proto definition modules %s", error)
        raise
finally:
    if commander and tmpdir:
        commander.cmd_nostatus(f"rm -rf {tmpdir}")


class GRPCClient:
    def __init__(self, server, port):
        self.channel = grpc.insecure_channel("{}:{}".format(server, port))
        self.stub = frr_northbound_pb2_grpc.NorthboundStub(self.channel)
        self.health_stub = health_pb2_grpc.HealthStub(self.channel)

    def check_health(self, service_name="", timeout=5):
        """Check health status of a service.

        Args:
          service_name: Name of the service to check (empty for default).
          timeout: Timeout in seconds for the health check (default 5s).

        Returns:
          Health status: SERVING, NOT_SERVING, UNKNOWN, SERVICE_UNKNOWN
          RPC error code: UNIMPLEMENTED, NOT_FOUND, UNAVAILABLE, DEADLINE_EXCEEDED, etc.
        """
        request = health_pb2.HealthCheckRequest(service=service_name)
        try:
            response = self.health_stub.Check(request, timeout=timeout)
            status_map = {
                health_pb2.HealthCheckResponse.UNKNOWN: "UNKNOWN",
                health_pb2.HealthCheckResponse.SERVING: "SERVING",
                health_pb2.HealthCheckResponse.NOT_SERVING: "NOT_SERVING",
                health_pb2.HealthCheckResponse.SERVICE_UNKNOWN: "SERVICE_UNKNOWN",
            }
            status = status_map.get(response.status, f"UNKNOWN({response.status})")
            logging.debug("Health check for '%s': %s", service_name, status)
            return status
        except grpc.RpcError as error:
            logging.debug("Health check failed: %s", error)
            return error.code().name

    def get_capabilities(self):
        request = frr_northbound_pb2.GetCapabilitiesRequest()
        response = "NONE"
        try:
            response = self.stub.GetCapabilities(request)
        except Exception as error:
            logging.error("Got exception from stub: %s", error)

        logging.debug("GRPC Capabilities: %s", response)
        return response

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
    parser.add_argument("--xml", action="store_true", help="encode XML instead of JSON")
    parser.add_argument("actions", nargs="*", help="GETCAP|GET,xpath|HEALTH,service")
    args = parser.parse_args(*args)

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: GRPC-CLI-CLIENT: %(name)s %(message)s",
    )

    if args.check:
        sys.exit(0)

    encoding = frr_northbound_pb2.XML if args.xml else frr_northbound_pb2.JSON

    c = GRPCClient(args.server, args.port)

    for action in next_action(args.actions):
        action_lower = action.casefold()
        logging.debug("GOT ACTION: %s", action)
        if action_lower == "getcap":
            caps = c.get_capabilities()
            print(caps)
        elif action_lower.startswith("get,"):
            # Get and print config and state
            _, xpath = action.split(",", 1)
            logging.debug("Get XPath: %s", xpath)
            print(c.get(xpath, encoding, gtype=frr_northbound_pb2.GetRequest.ALL))
        elif action_lower.startswith("get-config,"):
            # Get and print config
            _, xpath = action.split(",", 1)
            logging.debug("Get Config XPath: %s", xpath)
            print(c.get(xpath, encoding, gtype=frr_northbound_pb2.GetRequest.CONFIG))
        elif action_lower.startswith("get-state,"):
            # Get and print state
            _, xpath = action.split(",", 1)
            logging.debug("Get State XPath: %s", xpath)
            print(c.get(xpath, encoding, gtype=frr_northbound_pb2.GetRequest.STATE))
        elif action_lower.startswith("health"):
            # Check health status - preserve case for service name
            if "," in action:
                _, service = action.split(",", 1)
            else:
                service = ""
            status = c.check_health(service)
            print("Health[{}]: {}".format(service, status))


if __name__ == "__main__":
    main()
