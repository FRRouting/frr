#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: MIT
#
# February 22 2022, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2022, LabN Consulting, L.L.C.

import argparse
import concurrent.futures
import json
import logging
import os
import sys
import tempfile
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
TOPOTESTS_DIR = os.path.dirname(CWD)
if TOPOTESTS_DIR not in sys.path:
    sys.path.insert(0, TOPOTESTS_DIR)

tmpdir = None
commander = None
proto_dir = os.path.realpath(os.path.join(CWD, "../../../grpc"))
proto_file = os.path.join(proto_dir, "frr-northbound.proto")

try:
    # Make sure we don't run-into ourselves in parallel operating environment
    tmpdir = tempfile.mkdtemp(prefix="grpc-client-")

    # This is painful but works if you have installed grpc and grpc_tools would be *way*
    # better if we actually built and installed these but ... python packaging.
    try:
        import grpc_tools
        from munet.base import commander

        import grpc

        commander.cmd_raises(
            "python3 -m grpc_tools.protoc"
            f" --python_out={tmpdir} --grpc_python_out={tmpdir}"
            f" -I {proto_dir} {proto_file}"
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
    if commander and tmpdir:
        commander.cmd_nostatus(f"rm -rf {tmpdir}")


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

    def get(self, xpath, encoding, gtype, include_path=False):
        request = frr_northbound_pb2.GetRequest()
        if xpath is not None:
            request.path.append(xpath)
        request.type = gtype
        request.encoding = encoding
        responses = []
        result = ""
        for r in self.stub.Get(request):
            logging.debug('GRPC Get path: "%s" value: %s', request.path, r)
            if include_path:
                responses.append(f"{r.data.path}\n{r.data.data}")
            else:
                result += str(r.data.data)
        if include_path:
            return "\n".join(responses)
        return result

    def execute(self, xpath, input_values):
        request = frr_northbound_pb2.ExecuteRequest()
        request.path = xpath
        for path, value in input_values:
            pv = request.input.add()
            pv.path = path
            pv.value = value
        return self.stub.Execute(request)

    @staticmethod
    def _execute_request(xpath, input_values):
        request = frr_northbound_pb2.ExecuteRequest()
        request.path = xpath
        for path, value in input_values:
            pv = request.input.add()
            pv.path = path
            pv.value = value
        return request

    def execute_cancel(self, xpath, input_values, delay, timeout):
        request = self._execute_request(xpath, input_values)
        future = self.stub.Execute.future(request, timeout=timeout)
        time.sleep(delay)
        future.cancel()

        try:
            future.result()
        except grpc.FutureCancelledError:
            return "CANCELLED"
        except grpc.RpcError as error:
            return error.code().name

        return "OK"

    def execute_concurrent(self, xpath, input_values, count, timeout):
        def run_one():
            request = self._execute_request(xpath, input_values)
            try:
                self.stub.Execute(request, timeout=timeout)
                return "OK"
            except grpc.RpcError as error:
                return error.code().name

        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as executor:
            return json.dumps(list(executor.map(lambda _: run_one(), range(count))))

    def subscribe_listen(self, xpath, encoding, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.ON_CHANGE
        request.response_encoding = encoding
        request.path.append(xpath)

        for response in self.stub.Subscribe(request, timeout=timeout):
            if response.HasField("update"):
                return response.update.data
        return ""

    def subscribe_listen_with_path(self, xpath, encoding, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.ON_CHANGE
        request.response_encoding = encoding
        request.path.append(xpath)

        for response in self.stub.Subscribe(request, timeout=timeout):
            if response.HasField("update"):
                return json.dumps(
                    {
                        "path": response.update.path,
                        "data": response.update.data,
                    }
                )
        return ""

    def subscribe_until_sync(self, xpath, encoding, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.STREAM
        request.response_encoding = encoding
        request.path.append(xpath)

        responses = []
        for response in self.stub.Subscribe(request, timeout=timeout):
            if response.HasField("update"):
                responses.append(
                    {
                        "update": response.update.data,
                        "path": response.update.path,
                    }
                )
            elif response.HasField("sync_response"):
                responses.append({"sync_response": True})
                return json.dumps(responses)
        return json.dumps(responses)

    def subscribe_until_heartbeat(self, xpath, heartbeat_ms, encoding, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.ON_CHANGE
        request.response_encoding = encoding
        request.heartbeat_interval_ms = heartbeat_ms
        request.path.append(xpath)

        for response in self.stub.Subscribe(request, timeout=timeout):
            if response.HasField("heartbeat"):
                return "heartbeat"
        return ""

    def subscribe_cancel(self, xpath, encoding, delay, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.ON_CHANGE
        request.response_encoding = encoding
        request.path.append(xpath)

        call = self.stub.Subscribe(request, timeout=timeout)
        time.sleep(delay)
        call.cancel()

        try:
            list(call)
        except grpc.RpcError as error:
            return error.code().name

        return "OK"

    def subscribe_expect_shutdown(self, xpath, encoding, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.ON_CHANGE
        request.response_encoding = encoding
        request.path.append(xpath)

        try:
            list(self.stub.Subscribe(request, timeout=timeout))
        except grpc.RpcError as error:
            return error.code().name

        return "OK"

    def subscribe_sample_count(self, xpath, interval_ms, count, encoding, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.SAMPLE
        request.response_encoding = encoding
        request.sample_interval_ms = interval_ms
        request.path.append(xpath)

        responses = []
        for response in self.stub.Subscribe(request, timeout=timeout):
            if response.HasField("update"):
                responses.append(
                    {
                        "path": response.update.path,
                        "data": response.update.data,
                    }
                )
                if len(responses) >= count:
                    return json.dumps(responses)
        return json.dumps(responses)

    def subscribe_expect_error(self, mode, xpath, expected, encoding, timeout):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = getattr(frr_northbound_pb2.SubscribeRequest, mode)
        request.response_encoding = encoding
        if xpath:
            request.path.append(xpath)
        if mode == "SAMPLE":
            request.sample_interval_ms = 100

        try:
            list(self.stub.Subscribe(request, timeout=timeout))
        except grpc.RpcError as error:
            code = error.code().name
            if code != expected:
                raise AssertionError(f"expected {expected}, got {code}") from error
            return code

        raise AssertionError(f"expected {expected}, got OK")

    def subscribe_invalid_encoding_expect_error(
        self, mode, xpath, bad_encoding, expected, timeout
    ):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = getattr(frr_northbound_pb2.SubscribeRequest, mode)
        request.response_encoding = bad_encoding
        request.path.append(xpath)
        if mode == "SAMPLE":
            request.sample_interval_ms = 100

        try:
            list(self.stub.Subscribe(request, timeout=timeout))
        except grpc.RpcError as error:
            code = error.code().name
            if code != expected:
                raise AssertionError(f"expected {expected}, got {code}") from error
            return code

        raise AssertionError(f"expected {expected}, got OK")

    def subscribe_sample_expect_error(
        self, xpath, interval_ms, expected, encoding, timeout
    ):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.SAMPLE
        request.response_encoding = encoding
        request.sample_interval_ms = interval_ms
        if xpath:
            request.path.append(xpath)

        try:
            list(self.stub.Subscribe(request, timeout=timeout))
        except grpc.RpcError as error:
            code = error.code().name
            if code != expected:
                raise AssertionError(f"expected {expected}, got {code}") from error
            return code

        raise AssertionError(f"expected {expected}, got OK")

    def subscribe_stream_repeat_expect_error(
        self, xpath, repeat, expected, encoding, timeout
    ):
        request = frr_northbound_pb2.SubscribeRequest()
        request.mode = frr_northbound_pb2.SubscribeRequest.STREAM
        request.response_encoding = encoding
        for _ in range(repeat):
            request.path.append(xpath)

        try:
            list(self.stub.Subscribe(request, timeout=timeout))
        except grpc.RpcError as error:
            code = error.code().name
            if code != expected:
                raise AssertionError(f"expected {expected}, got {code}") from error
            return code

        raise AssertionError(f"expected {expected}, got OK")


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
    parser.add_argument("actions", nargs="*", help="GETCAP|GET,xpath")
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
        raw_action = action
        action = action.casefold()
        logging.debug("GOT ACTION: %s", action)
        if action == "getcap":
            caps = c.get_capabilities()
            print(caps)
        elif action == "get-config":
            print(
                c.get(
                    None,
                    encoding,
                    gtype=frr_northbound_pb2.GetRequest.CONFIG,
                )
            )
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
        elif action.startswith("get-config-with-path,"):
            _, xpath = action.split(",", 1)
            logging.debug("Get Config XPath: %s", xpath)
            print(
                c.get(
                    xpath,
                    encoding,
                    gtype=frr_northbound_pb2.GetRequest.CONFIG,
                    include_path=True,
                )
            )
        elif action.startswith("get-state,"):
            # Get and print state
            _, xpath = action.split(",", 1)
            logging.debug("Get State XPath: %s", xpath)
            print(c.get(xpath, encoding, gtype=frr_northbound_pb2.GetRequest.STATE))
            # for _ in range(0, 1):
        elif action.startswith("exec,"):
            # Execute an RPC. Input arguments are path=value pairs.
            parts = raw_action.split(",")
            xpath = parts[1]
            input_values = []
            for item in parts[2:]:
                path, value = item.split("=", 1)
                input_values.append((path, value))
            response = c.execute(xpath, input_values)
            print(response)
        elif action.startswith("exec-cancel,"):
            parts = raw_action.split(",")
            xpath = parts[1]
            delay = float(parts[2])
            timeout = float(parts[3])
            input_values = []
            for item in parts[4:]:
                path, value = item.split("=", 1)
                input_values.append((path, value))
            print(c.execute_cancel(xpath, input_values, delay, timeout))
        elif action.startswith("exec-concurrent,"):
            parts = raw_action.split(",")
            xpath = parts[1]
            count = int(parts[2])
            timeout = float(parts[3])
            input_values = []
            for item in parts[4:]:
                path, value = item.split("=", 1)
                input_values.append((path, value))
            print(c.execute_concurrent(xpath, input_values, count, timeout))
        elif action.startswith("subscribe-listen,"):
            _, xpath, timeout = raw_action.split(",", 2)
            print(c.subscribe_listen(xpath, encoding, float(timeout)))
        elif action.startswith("subscribe-listen-with-path,"):
            _, xpath, timeout = raw_action.split(",", 2)
            print(c.subscribe_listen_with_path(xpath, encoding, float(timeout)))
        elif action.startswith("subscribe-until-sync,"):
            _, xpath, timeout = raw_action.split(",", 2)
            print(c.subscribe_until_sync(xpath, encoding, float(timeout)))
        elif action.startswith("subscribe-until-heartbeat,"):
            _, xpath, heartbeat_ms, timeout = raw_action.split(",", 3)
            print(
                c.subscribe_until_heartbeat(
                    xpath, int(heartbeat_ms), encoding, float(timeout)
                )
            )
        elif action.startswith("subscribe-cancel,"):
            _, xpath, delay, timeout = raw_action.split(",", 3)
            print(c.subscribe_cancel(xpath, encoding, float(delay), float(timeout)))
        elif action.startswith("subscribe-expect-shutdown,"):
            _, xpath, timeout = raw_action.split(",", 2)
            print(c.subscribe_expect_shutdown(xpath, encoding, float(timeout)))
        elif action.startswith("subscribe-sample-count,"):
            _, xpath, interval_ms, count, timeout = raw_action.split(",", 4)
            print(
                c.subscribe_sample_count(
                    xpath, int(interval_ms), int(count), encoding, float(timeout)
                )
            )
        elif action.startswith("subscribe-expect-error,"):
            _, mode, xpath, expected, timeout = raw_action.split(",", 4)
            print(
                c.subscribe_expect_error(
                    mode, xpath, expected, encoding, float(timeout)
                )
            )
        elif action.startswith("subscribe-sample-expect-error,"):
            _, xpath, interval_ms, expected, timeout = raw_action.split(",", 4)
            print(
                c.subscribe_sample_expect_error(
                    xpath, int(interval_ms), expected, encoding, float(timeout)
                )
            )
        elif action.startswith("subscribe-invalid-encoding-expect-error,"):
            _, mode, xpath, bad_encoding, expected, timeout = raw_action.split(",", 5)
            print(
                c.subscribe_invalid_encoding_expect_error(
                    mode, xpath, int(bad_encoding), expected, float(timeout)
                )
            )
        elif action.startswith("subscribe-stream-repeat-expect-error,"):
            _, xpath, repeat, expected, timeout = raw_action.split(",", 4)
            print(
                c.subscribe_stream_repeat_expect_error(
                    xpath, int(repeat), expected, encoding, float(timeout)
                )
            )


if __name__ == "__main__":
    main()
