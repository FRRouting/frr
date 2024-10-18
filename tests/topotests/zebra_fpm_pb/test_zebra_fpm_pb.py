#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright (C) 2023 Alibaba, Inc. Hongyu Li
#

"""
test_zebra_fpm_pb.py: Test the FRR Zebra dplane_fpm_pb
"""
import os
import sys
import pytest
import json
import functools
from time import sleep
# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.dplane]

def setup_module(mod):
    "Sets up the pytest environment"
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r2", "r3"),
        "s3": ("r2", "r4"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        print(f"starting dplaneserver for {rname}")
        router.start_dplane_server()

    for rname, router in router_list.items():
        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        router.load_config(TopoRouter.RD_ZEBRA, daemon_file,"-M dplane_fpm_pb")

        daemon_file = "{}/{}/bgpd.conf".format(CWD, rname)
        router.load_config(TopoRouter.RD_BGP, daemon_file)
    # Initialize all routers.
    tgen.start_router()
    logger.info("start test routers failure")
    # Verify if routers are running
    for rname, router in router_list.items():
        result = router.check_router_running()
        if result != "":
            logger.info("{} router running failure".format(rname))
            pytest.skip(result)

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()

def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            content=f.read()
            if content=="":
                 return json.loads("[]")
            return json.loads(content)
    except IOError:
        assert False, "Could not read file {}".format(filename)

def do_check(name,result_file, expected_file):
    def format_json_file(file):
        f=open(file,"r+")
        content=f.read()
        if len(content) == 0 or content[0] == '[':
            logger.info(" {} doesn't need formatting".format(file))
            f.close()
            return
        logger.info("origin outfile is:")
        logger.info(content)
        content=content.replace("}","},",content.count("}")-1)
        content="[\n"+content+"\n]"
        f.close()
        f=open(file,"w+")
        f.write(content)
        f.close()
        logger.info("outfile is:")
        logger.info(content)

    def _check(name,result_file, expected_file):
        logger.info("polling")

        tgen = get_topogen()
        router = tgen.gears[name]
        dir_path = f"{router.logdir}/{router.name}"
        json_path = f"{dir_path}/{result_file}"
        fpm_log_file = "dplaneserver.log"
        log_path = f"{dir_path}/{fpm_log_file}"
        fp = open(log_path,"r+")
        log_content = fp.read()
        logger.info(log_content)
        fp.close()

        format_json_file(json_path)
        output = open_json_file(json_path)
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, result_file, expected_file))
    tgen = get_topogen()
    result = _check(name, result_file, expected_file)
    assert result is None, "Failed"

def test_zebra_dplane_fpm_pb():
    logger.info("start test_zebra_dplane_fpm_pb")
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    sleep(5)
    do_check("r1", "output.json", "r1/ref.json")
