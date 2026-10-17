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

    def commit(self, xpath, value):
        """
        Commit a single xpath/value change to the running configuration.

        This creates a candidate, edits it, commits it, and cleans up.
        Returns "COMMIT OK" on success, raises exception on failure.
        """
        candidate_id = None
        try:
            # Step 1: Create a candidate configuration
            create_req = frr_northbound_pb2.CreateCandidateRequest()
            create_resp = self.stub.CreateCandidate(create_req)
            candidate_id = create_resp.candidate_id
            logging.info("Created candidate %d", candidate_id)

            # Step 2: Edit the candidate with the xpath/value
            edit_req = frr_northbound_pb2.EditCandidateRequest()
            edit_req.candidate_id = candidate_id
            path_value = edit_req.update.add()
            path_value.path = xpath
            path_value.value = value
            self.stub.EditCandidate(edit_req)
            logging.info("Edited candidate %d: %s = %s", candidate_id, xpath, value)

            # Step 3: Commit the candidate (phase=ALL)
            commit_req = frr_northbound_pb2.CommitRequest()
            commit_req.candidate_id = candidate_id
            commit_req.phase = frr_northbound_pb2.CommitRequest.ALL
            commit_req.comment = "grpc-query.py commit"
            self.stub.Commit(commit_req)
            logging.info("Committed candidate %d", candidate_id)

            # Step 4: Delete the candidate (cleanup)
            try:
                delete_req = frr_northbound_pb2.DeleteCandidateRequest()
                delete_req.candidate_id = candidate_id
                self.stub.DeleteCandidate(delete_req)
                logging.info("Deleted candidate %d", candidate_id)
            except Exception as e:
                logging.warning("Failed to delete candidate %d: %s", candidate_id, e)
            candidate_id = None

            return "COMMIT OK"

        except Exception as error:
            logging.error("Commit failed: %s", error)
            if candidate_id is not None:
                try:
                    delete_req = frr_northbound_pb2.DeleteCandidateRequest()
                    delete_req.candidate_id = candidate_id
                    self.stub.DeleteCandidate(delete_req)
                except Exception:
                    pass
            raise

    def delete(self, xpath):
        """
        Delete an xpath from the running configuration.

        This creates a candidate, adds a delete operation, commits it, and cleans up.
        Returns "DELETE OK" on success, raises exception on failure.
        """
        candidate_id = None
        try:
            # Step 1: Create a candidate configuration
            create_req = frr_northbound_pb2.CreateCandidateRequest()
            create_resp = self.stub.CreateCandidate(create_req)
            candidate_id = create_resp.candidate_id
            logging.info("Created candidate %d", candidate_id)

            # Step 2: Add delete operation for the xpath
            edit_req = frr_northbound_pb2.EditCandidateRequest()
            edit_req.candidate_id = candidate_id
            path_value = edit_req.delete.add()
            path_value.path = xpath
            self.stub.EditCandidate(edit_req)
            logging.info("Added delete for candidate %d: %s", candidate_id, xpath)

            # Step 3: Commit the candidate (phase=ALL)
            commit_req = frr_northbound_pb2.CommitRequest()
            commit_req.candidate_id = candidate_id
            commit_req.phase = frr_northbound_pb2.CommitRequest.ALL
            commit_req.comment = "grpc-query.py delete"
            self.stub.Commit(commit_req)
            logging.info("Committed candidate %d", candidate_id)

            # Step 4: Delete the candidate (cleanup)
            try:
                delete_req = frr_northbound_pb2.DeleteCandidateRequest()
                delete_req.candidate_id = candidate_id
                self.stub.DeleteCandidate(delete_req)
                logging.info("Deleted candidate %d", candidate_id)
            except Exception as e:
                logging.warning("Failed to delete candidate %d: %s", candidate_id, e)
            candidate_id = None

            return "DELETE OK"

        except Exception as error:
            logging.error("Delete failed: %s", error)
            if candidate_id is not None:
                try:
                    delete_req = frr_northbound_pb2.DeleteCandidateRequest()
                    delete_req.candidate_id = candidate_id
                    self.stub.DeleteCandidate(delete_req)
                except Exception:
                    pass
            raise


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
    parser.add_argument(
        "actions", nargs="*", help="GETCAP|GET,xpath|COMMIT,xpath:::value|DELETE,xpath"
    )
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
        elif action_lower.startswith("commit,"):
            # Commit a single xpath/value change
            # Format: COMMIT,xpath:::value (using ::: separator since both
            # xpath and value may contain commas)
            _, rest = action.split(",", 1)
            if ":::" not in rest:
                print("ERROR: COMMIT requires format: COMMIT,xpath:::value")
                sys.exit(1)
            xpath, value = rest.split(":::", 1)
            if not xpath:
                print("ERROR: COMMIT requires format: COMMIT,xpath:::value")
                sys.exit(1)
            try:
                result = c.commit(xpath, value)
                print(result)
            except Exception as error:
                print("COMMIT FAILED: {}".format(error))
                sys.exit(1)
        elif action_lower.startswith("delete,"):
            # Delete an xpath from the configuration
            _, xpath = action.split(",", 1)
            if not xpath:
                print("ERROR: DELETE requires format: DELETE,xpath")
                sys.exit(1)
            try:
                result = c.delete(xpath)
                print(result)
            except Exception as error:
                print("DELETE FAILED: {}".format(error))
                sys.exit(1)
        else:
            print("ERROR: Unknown action: {}".format(action))
            sys.exit(1)


if __name__ == "__main__":
    main()
