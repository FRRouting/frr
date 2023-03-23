# SPDX-License-Identifier: ISC
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#

import ipaddress
import json
import os
import platform
import socket
import subprocess
import sys
import traceback
import functools
from collections import OrderedDict
from copy import deepcopy
from datetime import datetime, timedelta
from functools import wraps
from re import search as re_search
from time import sleep

try:
    # Imports from python2
    import ConfigParser as configparser
except ImportError:
    # Imports from python3
    import configparser

from lib.micronet import comm_error
from lib.topogen import TopoRouter, get_topogen
from lib.topolog import get_logger, logger
from lib.topotest import frr_unicode, interface_set_status, version_cmp
from lib import topotest

FRRCFG_FILE = "frr_json.conf"
FRRCFG_BKUP_FILE = "frr_json_initial.conf"

ERROR_LIST = ["Malformed", "Failure", "Unknown", "Incomplete"]

####
CD = os.path.dirname(os.path.realpath(__file__))
PYTESTINI_PATH = os.path.join(CD, "../pytest.ini")

# NOTE: to save execution logs to log file frrtest_log_dir must be configured
# in `pytest.ini`.
config = configparser.ConfigParser()
config.read(PYTESTINI_PATH)

config_section = "topogen"

# Debug logs for daemons
DEBUG_LOGS = {
    "pimd": [
        "debug msdp events",
        "debug msdp packets",
        "debug igmp events",
        "debug igmp trace",
        "debug mroute",
        "debug mroute detail",
        "debug pim events",
        "debug pim packets",
        "debug pim trace",
        "debug pim zebra",
        "debug pim bsm",
        "debug pim packets joins",
        "debug pim packets register",
        "debug pim nht",
    ],
    "pim6d": [
        "debug pimv6 events",
        "debug pimv6 packets",
        "debug pimv6 packet-dump send",
        "debug pimv6 packet-dump receive",
        "debug pimv6 trace",
        "debug pimv6 trace detail",
        "debug pimv6 zebra",
        "debug pimv6 bsm",
        "debug pimv6 packets hello",
        "debug pimv6 packets joins",
        "debug pimv6 packets register",
        "debug pimv6 nht",
        "debug pimv6 nht detail",
        "debug mroute6",
        "debug mroute6 detail",
        "debug mld events",
        "debug mld packets",
        "debug mld trace",
    ],
    "bgpd": [
        "debug bgp neighbor-events",
        "debug bgp updates",
        "debug bgp zebra",
        "debug bgp nht",
        "debug bgp neighbor-events",
        "debug bgp graceful-restart",
        "debug bgp update-groups",
        "debug bgp vpn leak-from-vrf",
        "debug bgp vpn leak-to-vrf",
        "debug bgp zebr",
        "debug bgp updates",
        "debug bgp nht",
        "debug bgp neighbor-events",
        "debug vrf",
    ],
    "zebra": [
        "debug zebra events",
        "debug zebra rib",
        "debug zebra vxlan",
        "debug zebra nht",
    ],
    "mgmt": [],
    "ospf": [
        "debug ospf event",
        "debug ospf ism",
        "debug ospf lsa",
        "debug ospf nsm",
        "debug ospf nssa",
        "debug ospf packet all",
        "debug ospf sr",
        "debug ospf te",
        "debug ospf zebra",
    ],
    "ospf6": [
        "debug ospf6 event",
        "debug ospf6 ism",
        "debug ospf6 lsa",
        "debug ospf6 nsm",
        "debug ospf6 nssa",
        "debug ospf6 packet all",
        "debug ospf6 sr",
        "debug ospf6 te",
        "debug ospf6 zebra",
    ],
}

g_iperf_client_procs = {}
g_iperf_server_procs = {}


def is_string(value):
    try:
        return isinstance(value, basestring)
    except NameError:
        return isinstance(value, str)


if config.has_option("topogen", "verbosity"):
    loglevel = config.get("topogen", "verbosity")
    loglevel = loglevel.lower()
else:
    loglevel = "info"

if config.has_option("topogen", "frrtest_log_dir"):
    frrtest_log_dir = config.get("topogen", "frrtest_log_dir")
    time_stamp = datetime.time(datetime.now())
    logfile_name = "frr_test_bgp_"
    frrtest_log_file = frrtest_log_dir + logfile_name + str(time_stamp)
    print("frrtest_log_file..", frrtest_log_file)

    logger = get_logger(
        "test_execution_logs", log_level=loglevel, target=frrtest_log_file
    )
    print("Logs will be sent to logfile: {}".format(frrtest_log_file))

if config.has_option("topogen", "show_router_config"):
    show_router_config = config.get("topogen", "show_router_config")
else:
    show_router_config = False

# env variable for setting what address type to test
ADDRESS_TYPES = os.environ.get("ADDRESS_TYPES")


# Saves sequence id numbers
SEQ_ID = {"prefix_lists": {}, "route_maps": {}}


def get_seq_id(obj_type, router, obj_name):
    """
    Generates and saves sequence number in interval of 10
    Parameters
    ----------
    * `obj_type`: prefix_lists or route_maps
    * `router`: router name
    *` obj_name`: name of the prefix-list or route-map
    Returns
    --------
    Sequence number generated
    """

    router_data = SEQ_ID[obj_type].setdefault(router, {})
    obj_data = router_data.setdefault(obj_name, {})
    seq_id = obj_data.setdefault("seq_id", 0)

    seq_id = int(seq_id) + 10
    obj_data["seq_id"] = seq_id

    return seq_id


def set_seq_id(obj_type, router, id, obj_name):
    """
    Saves sequence number if not auto-generated and given by user
    Parameters
    ----------
    * `obj_type`: prefix_lists or route_maps
    * `router`: router name
    *` obj_name`: name of the prefix-list or route-map
    """
    router_data = SEQ_ID[obj_type].setdefault(router, {})
    obj_data = router_data.setdefault(obj_name, {})
    seq_id = obj_data.setdefault("seq_id", 0)

    seq_id = int(seq_id) + int(id)
    obj_data["seq_id"] = seq_id


class InvalidCLIError(Exception):
    """Raise when the CLI command is wrong"""


def run_frr_cmd(rnode, cmd, isjson=False):
    """
    Execute frr show commands in privileged mode
    * `rnode`: router node on which command needs to be executed
    * `cmd`: Command to be executed on frr
    * `isjson`: If command is to get json data or not
    :return str:
    """

    if cmd:
        ret_data = rnode.vtysh_cmd(cmd, isjson=isjson)

        if isjson:
            rnode.vtysh_cmd(cmd.rstrip("json"), isjson=False)

        return ret_data

    else:
        raise InvalidCLIError("No actual cmd passed")


def apply_raw_config(tgen, input_dict):

    """
    API to configure raw configuration on device. This can be used for any cli
    which has not been implemented in JSON.

    Parameters
    ----------
    * `tgen`: tgen object
    * `input_dict`: configuration that needs to be applied

    Usage
    -----
    input_dict = {
        "r2": {
            "raw_config": [
                "router bgp",
                "no bgp update-group-split-horizon"
            ]
        }
    }
    Returns
    -------
    True or errormsg
    """

    rlist = []

    for router_name in input_dict.keys():
        config_cmd = input_dict[router_name]["raw_config"]

        if not isinstance(config_cmd, list):
            config_cmd = [config_cmd]

        frr_cfg_file = "{}/{}/{}".format(tgen.logdir, router_name, FRRCFG_FILE)
        with open(frr_cfg_file, "w") as cfg:
            for cmd in config_cmd:
                cfg.write("{}\n".format(cmd))

        rlist.append(router_name)

    # Load config on all routers
    return load_config_to_routers(tgen, rlist)


def create_common_configurations(
    tgen, config_dict, config_type=None, build=False, load_config=True
):
    """
    API to create object of class FRRConfig and also create frr_json.conf
    file. It will create interface and common configurations and save it to
    frr_json.conf and load to router
    Parameters
    ----------
    * `tgen`: tgen object
    * `config_dict`: Configuration data saved in a dict of { router: config-list }
    * `routers` : list of router id to be configured.
    * `config_type` : Syntactic information while writing configuration. Should
                      be one of the value as mentioned in the config_map below.
    * `build` : Only for initial setup phase this is set as True
    Returns
    -------
    True or False
    """

    config_map = OrderedDict(
        {
            "general_config": "! FRR General Config\n",
            "debug_log_config": "! Debug log Config\n",
            "interface_config": "! Interfaces Config\n",
            "static_route": "! Static Route Config\n",
            "prefix_list": "! Prefix List Config\n",
            "bgp_community_list": "! Community List Config\n",
            "route_maps": "! Route Maps Config\n",
            "bgp": "! BGP Config\n",
            "vrf": "! VRF Config\n",
            "ospf": "! OSPF Config\n",
            "ospf6": "! OSPF Config\n",
            "pim": "! PIM Config\n",
        }
    )

    if build:
        mode = "a"
    elif not load_config:
        mode = "a"
    else:
        mode = "w"

    routers = config_dict.keys()
    for router in routers:
        fname = "{}/{}/{}".format(tgen.logdir, router, FRRCFG_FILE)
        try:
            frr_cfg_fd = open(fname, mode)
            if config_type:
                frr_cfg_fd.write(config_map[config_type])
            for line in config_dict[router]:
                frr_cfg_fd.write("{} \n".format(str(line)))
            frr_cfg_fd.write("\n")

        except IOError as err:
            logger.error("Unable to open FRR Config '%s': %s" % (fname, str(err)))
            return False
        finally:
            frr_cfg_fd.close()

    # If configuration applied from build, it will done at last
    result = True
    if not build and load_config:
        result = load_config_to_routers(tgen, routers)

    return result


def create_common_configuration(
    tgen, router, data, config_type=None, build=False, load_config=True
):
    """
    API to create object of class FRRConfig and also create frr_json.conf
    file. It will create interface and common configurations and save it to
    frr_json.conf and load to router
    Parameters
    ----------
    * `tgen`: tgen object
    * `data`: Configuration data saved in a list.
    * `router` : router id to be configured.
    * `config_type` : Syntactic information while writing configuration. Should
                      be one of the value as mentioned in the config_map below.
    * `build` : Only for initial setup phase this is set as True
    Returns
    -------
    True or False
    """
    return create_common_configurations(
        tgen, {router: data}, config_type, build, load_config
    )


def kill_router_daemons(tgen, router, daemons, save_config=True):
    """
    Router's current config would be saved to /etc/frr/ for each daemon
    and daemon would be killed forcefully using SIGKILL.
    * `tgen`  : topogen object
    * `router`: Device under test
    * `daemons`: list of daemons to be killed
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        router_list = tgen.routers()

        if save_config:
            # Saving router config to /etc/frr, which will be loaded to router
            # when it starts
            router_list[router].vtysh_cmd("write memory")

        # Kill Daemons
        result = router_list[router].killDaemons(daemons)
        if len(result) > 0:
            assert "Errors found post shutdown - details follow:" == 0, result
        return result

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg


def start_router_daemons(tgen, router, daemons):
    """
    Daemons defined by user would be started
    * `tgen`  : topogen object
    * `router`: Device under test
    * `daemons`: list of daemons to be killed
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        router_list = tgen.routers()

        # Start daemons
        res = router_list[router].startDaemons(daemons)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        res = errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return res


def check_router_status(tgen):
    """
    Check if all daemons are running for all routers in topology
    * `tgen`  : topogen object
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        router_list = tgen.routers()
        for router, rnode in router_list.items():

            result = rnode.check_router_running()
            if result != "":
                daemons = []
                if "mgmtd" in result:
                    daemons.append("mgmtd")
                if "bgpd" in result:
                    daemons.append("bgpd")
                if "zebra" in result:
                    daemons.append("zebra")
                if "pimd" in result:
                    daemons.append("pimd")
                if "pim6d" in result:
                    daemons.append("pim6d")
                if "ospfd" in result:
                    daemons.append("ospfd")
                if "ospf6d" in result:
                    daemons.append("ospf6d")
                rnode.startDaemons(daemons)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def save_initial_config_on_routers(tgen):
    """Save current configuration on routers to FRRCFG_BKUP_FILE.

    FRRCFG_BKUP_FILE is the file that will be restored when `reset_config_on_routers()`
    is called.

    Parameters
    ----------
    * `tgen` : Topogen object
    """
    router_list = tgen.routers()
    target_cfg_fmt = tgen.logdir + "/{}/frr_json_initial.conf"

    # Get all running configs in parallel
    procs = {}
    for rname in router_list:
        logger.info("Fetching running config for router %s", rname)
        procs[rname] = router_list[rname].popen(
            ["/usr/bin/env", "vtysh", "-c", "show running-config no-header"],
            stdin=None,
            stdout=open(target_cfg_fmt.format(rname), "w"),
            stderr=subprocess.PIPE,
        )
    for rname, p in procs.items():
        _, error = p.communicate()
        if p.returncode:
            logger.error(
                "Get running config for %s failed %d: %s", rname, p.returncode, error
            )
            raise InvalidCLIError(
                "vtysh show running error on {}: {}".format(rname, error)
            )


def reset_config_on_routers(tgen, routerName=None):
    """
    Resets configuration on routers to the snapshot created using input JSON
    file. It replaces existing router configuration with FRRCFG_BKUP_FILE

    Parameters
    ----------
    * `tgen` : Topogen object
    * `routerName` : router config is to be reset
    """

    logger.debug("Entering API: reset_config_on_routers")

    tgen.cfg_gen += 1
    gen = tgen.cfg_gen

    # Trim the router list if needed
    router_list = tgen.routers()
    if routerName:
        if routerName not in router_list:
            logger.warning(
                "Exiting API: reset_config_on_routers: no router %s",
                routerName,
                exc_info=True,
            )
            return True
        router_list = {routerName: router_list[routerName]}

    delta_fmt = tgen.logdir + "/{}/delta-{}.conf"
    # FRRCFG_BKUP_FILE
    target_cfg_fmt = tgen.logdir + "/{}/frr_json_initial.conf"
    run_cfg_fmt = tgen.logdir + "/{}/frr-{}.sav"

    #
    # Get all running configs in parallel
    #
    procs = {}
    for rname in router_list:
        logger.info("Fetching running config for router %s", rname)
        procs[rname] = router_list[rname].popen(
            ["/usr/bin/env", "vtysh", "-c", "show running-config no-header"],
            stdin=None,
            stdout=open(run_cfg_fmt.format(rname, gen), "w"),
            stderr=subprocess.PIPE,
        )
    for rname, p in procs.items():
        _, error = p.communicate()
        if p.returncode:
            logger.error(
                "Get running config for %s failed %d: %s", rname, p.returncode, error
            )
            raise InvalidCLIError(
                "vtysh show running error on {}: {}".format(rname, error)
            )

    #
    # Get all delta's in parallel
    #
    procs = {}
    for rname in router_list:
        logger.info(
            "Generating delta for router %s to new configuration (gen %d)", rname, gen
        )
        procs[rname] = tgen.net.popen(
            [
                "/usr/lib/frr/frr-reload.py",
                "--test-reset",
                "--input",
                run_cfg_fmt.format(rname, gen),
                "--test",
                target_cfg_fmt.format(rname),
            ],
            stdin=None,
            stdout=open(delta_fmt.format(rname, gen), "w"),
            stderr=subprocess.PIPE,
        )
    for rname, p in procs.items():
        _, error = p.communicate()
        if p.returncode:
            logger.error(
                "Delta file creation for %s failed %d: %s", rname, p.returncode, error
            )
            raise InvalidCLIError("frr-reload error for {}: {}".format(rname, error))

    #
    # Apply all the deltas in parallel
    #
    procs = {}
    for rname in router_list:
        logger.info("Applying delta config on router %s", rname)

        procs[rname] = router_list[rname].popen(
            ["/usr/bin/env", "vtysh", "-f", delta_fmt.format(rname, gen)],
            stdin=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
    for rname, p in procs.items():
        output, _ = p.communicate()
        vtysh_command = "vtysh -f {}".format(delta_fmt.format(rname, gen))
        if not p.returncode:
            router_list[rname].logger.info(
                '\nvtysh config apply => "{}"\nvtysh output <= "{}"'.format(
                    vtysh_command, output
                )
            )
        else:
            router_list[rname].logger.warning(
                '\nvtysh config apply failed => "{}"\nvtysh output <= "{}"'.format(
                    vtysh_command, output
                )
            )
            logger.error(
                "Delta file apply for %s failed %d: %s", rname, p.returncode, output
            )

            # We really need to enable this failure; however, currently frr-reload.py
            # producing invalid "no" commands as it just preprends "no", but some of the
            # command forms lack matching values (e.g., final values). Until frr-reload
            # is fixed to handle this (or all the CLI no forms are adjusted) we can't
            # fail tests.
            # raise InvalidCLIError("frr-reload error for {}: {}".format(rname, output))

    #
    # Optionally log all new running config if "show_router_config" is defined in
    # "pytest.ini"
    #
    if show_router_config:
        procs = {}
        for rname in router_list:
            logger.info("Fetching running config for router %s", rname)
            procs[rname] = router_list[rname].popen(
                ["/usr/bin/env", "vtysh", "-c", "show running-config no-header"],
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        for rname, p in procs.items():
            output, _ = p.communicate()
            if p.returncode:
                logger.warning(
                    "Get running config for %s failed %d: %s",
                    rname,
                    p.returncode,
                    output,
                )
            else:
                logger.info(
                    "Configuration on router %s after reset:\n%s", rname, output
                )

    logger.debug("Exiting API: reset_config_on_routers")
    return True


def prep_load_config_to_routers(tgen, *config_name_list):
    """Create common config for `load_config_to_routers`.

    The common config file is constructed from the list of sub-config files passed as
    position arguments to this function. Each entry in `config_name_list` is looked for
    under the router sub-directory in the test directory and those files are
    concatenated together to create the common config. e.g.,

      # Routers are "r1" and "r2", test file is `example/test_example_foo.py`
      prepare_load_config_to_routers(tgen, "bgpd.conf", "ospfd.conf")

    When the above call is made the files in

      example/r1/bgpd.conf
      example/r1/ospfd.conf

    Are concat'd together into a single config file that will be loaded on r1, and

      example/r2/bgpd.conf
      example/r2/ospfd.conf

    Are concat'd together into a single config file that will be loaded on r2 when
    the call to `load_config_to_routers` is made.
    """

    routers = tgen.routers()
    for rname, router in routers.items():
        destname = "{}/{}/{}".format(tgen.logdir, rname, FRRCFG_FILE)
        wmode = "w"
        for cfbase in config_name_list:
            script_dir = os.environ["PYTEST_TOPOTEST_SCRIPTDIR"]
            confname = os.path.join(script_dir, "{}/{}".format(rname, cfbase))
            with open(confname, "r") as cf:
                with open(destname, wmode) as df:
                    df.write(cf.read())
            wmode = "a"


def load_config_to_routers(tgen, routers, save_bkup=False):
    """
    Loads configuration on routers from the file FRRCFG_FILE.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `routers` : routers for which configuration is to be loaded
    * `save_bkup` : If True, Saves snapshot of FRRCFG_FILE to FRRCFG_BKUP_FILE
    Returns
    -------
    True or False
    """

    logger.debug("Entering API: load_config_to_routers")

    tgen.cfg_gen += 1
    gen = tgen.cfg_gen

    base_router_list = tgen.routers()
    router_list = {}
    for router in routers:
        if router not in base_router_list:
            continue
        router_list[router] = base_router_list[router]

    frr_cfg_file_fmt = tgen.logdir + "/{}/" + FRRCFG_FILE
    frr_cfg_save_file_fmt = tgen.logdir + "/{}/{}-" + FRRCFG_FILE
    frr_cfg_bkup_fmt = tgen.logdir + "/{}/" + FRRCFG_BKUP_FILE

    procs = {}
    for rname in router_list:
        router = router_list[rname]
        try:
            frr_cfg_file = frr_cfg_file_fmt.format(rname)
            frr_cfg_save_file = frr_cfg_save_file_fmt.format(rname, gen)
            frr_cfg_bkup = frr_cfg_bkup_fmt.format(rname)
            with open(frr_cfg_file, "r+") as cfg:
                data = cfg.read()
                logger.info(
                    "Applying following configuration on router %s (gen: %d):\n%s",
                    rname,
                    gen,
                    data,
                )
                # Always save a copy of what we just did
                with open(frr_cfg_save_file, "w") as bkup:
                    bkup.write(data)
                if save_bkup:
                    with open(frr_cfg_bkup, "w") as bkup:
                        bkup.write(data)
            procs[rname] = router_list[rname].popen(
                ["/usr/bin/env", "vtysh", "-f", frr_cfg_file],
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except IOError as err:
            logger.error(
                "Unable to open config File. error(%s): %s", err.errno, err.strerror
            )
            return False
        except Exception as error:
            logger.error("Unable to apply config on %s: %s", rname, str(error))
            return False

    errors = []
    for rname, p in procs.items():
        output, _ = p.communicate()
        frr_cfg_file = frr_cfg_file_fmt.format(rname)
        vtysh_command = "vtysh -f " + frr_cfg_file
        if not p.returncode:
            router_list[rname].logger.info(
                '\nvtysh config apply => "{}"\nvtysh output <= "{}"'.format(
                    vtysh_command, output
                )
            )
        else:
            router_list[rname].logger.error(
                '\nvtysh config apply failed => "{}"\nvtysh output <= "{}"'.format(
                    vtysh_command, output
                )
            )
            logger.error(
                "Config apply for %s failed %d: %s", rname, p.returncode, output
            )
            # We can't thorw an exception here as we won't clear the config file.
            errors.append(
                InvalidCLIError(
                    "load_config_to_routers error for {}: {}".format(rname, output)
                )
            )

        # Empty the config file or we append to it next time through.
        with open(frr_cfg_file, "r+") as cfg:
            cfg.truncate(0)

    # Router current configuration to log file or console if
    # "show_router_config" is defined in "pytest.ini"
    if show_router_config:
        procs = {}
        for rname in router_list:
            procs[rname] = router_list[rname].popen(
                ["/usr/bin/env", "vtysh", "-c", "show running-config no-header"],
                stdin=None,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        for rname, p in procs.items():
            output, _ = p.communicate()
            if p.returncode:
                logger.warning(
                    "Get running config for %s failed %d: %s",
                    rname,
                    p.returncode,
                    output,
                )
            else:
                logger.info("New configuration for router %s:\n%s", rname, output)

    logger.debug("Exiting API: load_config_to_routers")
    return not errors


def load_config_to_router(tgen, routerName, save_bkup=False):
    """
    Loads configuration on router from the file FRRCFG_FILE.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `routerName` : router for which configuration to be loaded
    * `save_bkup` : If True, Saves snapshot of FRRCFG_FILE to FRRCFG_BKUP_FILE
    """
    return load_config_to_routers(tgen, [routerName], save_bkup)


def reset_with_new_configs(tgen, *cflist):
    """Reset the router to initial config, then load new configs.

    Resets routers to the initial config state (see `save_initial_config_on_routers()
    and `reset_config_on_routers()` `), then concat list of router sub-configs together
    and load onto the routers (see `prep_load_config_to_routers()` and
    `load_config_to_routers()`)
    """
    routers = tgen.routers()

    reset_config_on_routers(tgen)
    prep_load_config_to_routers(tgen, *cflist)
    load_config_to_routers(tgen, tgen.routers(), save_bkup=False)


def get_frr_ipv6_linklocal(tgen, router, intf=None, vrf=None):
    """
    API to get the link local ipv6 address of a particular interface using
    FRR command 'show interface'

    * `tgen`: tgen object
    * `router` : router for which highest interface should be
                 calculated
    * `intf` : interface for which link-local address needs to be taken
    * `vrf` : VRF name

    Usage
    -----
    linklocal = get_frr_ipv6_linklocal(tgen, router, "intf1", RED_A)

    Returns
    -------
    1) array of interface names to link local ips.
    """

    router_list = tgen.routers()
    for rname, rnode in router_list.items():
        if rname != router:
            continue

        linklocal = []

        if vrf:
            cmd = "show interface vrf {}".format(vrf)
        else:
            cmd = "show interface"

        linklocal = []
        if vrf:
            cmd = "show interface vrf {}".format(vrf)
        else:
            cmd = "show interface"
        for chk_ll in range(0, 60):
            sleep(1 / 4)
            ifaces = router_list[router].run('vtysh -c "{}"'.format(cmd))
            # Fix newlines (make them all the same)
            ifaces = ("\n".join(ifaces.splitlines()) + "\n").splitlines()

            interface = None
            ll_per_if_count = 0
            for line in ifaces:
                # Interface name
                m = re_search("Interface ([a-zA-Z0-9-]+) is", line)
                if m:
                    interface = m.group(1).split(" ")[0]
                    ll_per_if_count = 0

                # Interface ip
                m1 = re_search("inet6 (fe80[:a-fA-F0-9]+/[0-9]+)", line)
                if m1:
                    local = m1.group(1)
                    ll_per_if_count += 1
                    if ll_per_if_count > 1:
                        linklocal += [["%s-%s" % (interface, ll_per_if_count), local]]
                    else:
                        linklocal += [[interface, local]]

            try:
                if linklocal:
                    if intf:
                        return [
                            _linklocal[1]
                            for _linklocal in linklocal
                            if _linklocal[0] == intf
                        ][0].split("/")[0]
                    return linklocal
            except IndexError:
                continue

        errormsg = "Link local ip missing on router {}".format(router)
        return errormsg


def generate_support_bundle():
    """
    API to generate support bundle on any verification ste failure.
    it runs a python utility, /usr/lib/frr/generate_support_bundle.py,
    which basically runs defined CLIs and dumps the data to specified location
    """

    tgen = get_topogen()
    router_list = tgen.routers()
    test_name = os.environ.get("PYTEST_CURRENT_TEST").split(":")[-1].split(" ")[0]

    bundle_procs = {}
    for rname, rnode in router_list.items():
        logger.info("Spawn collection of support bundle for %s", rname)
        dst_bundle = "{}/{}/support_bundles/{}".format(tgen.logdir, rname, test_name)
        rnode.run("mkdir -p " + dst_bundle)

        gen_sup_cmd = [
            "/usr/lib/frr/generate_support_bundle.py",
            "--log-dir=" + dst_bundle,
        ]
        bundle_procs[rname] = tgen.net[rname].popen(gen_sup_cmd, stdin=None)

    for rname, rnode in router_list.items():
        logger.info("Waiting on support bundle for %s", rname)
        output, error = bundle_procs[rname].communicate()
        if output:
            logger.info(
                "Output from collecting support bundle for %s:\n%s", rname, output
            )
        if error:
            logger.warning(
                "Error from collecting support bundle for %s:\n%s", rname, error
            )

    return True


def start_topology(tgen):
    """
    Starting topology, create tmp files which are loaded to routers
    to start daemons and then start routers
    * `tgen`  : topogen object
    """

    # Starting topology
    tgen.start_topology()

    # Starting daemons

    router_list = tgen.routers()
    routers_sorted = sorted(
        router_list.keys(), key=lambda x: int(re_search("[0-9]+", x).group(0))
    )

    linux_ver = ""
    router_list = tgen.routers()
    for rname in routers_sorted:
        router = router_list[rname]

        # It will help in debugging the failures, will give more details on which
        # specific kernel version tests are failing
        if linux_ver == "":
            linux_ver = router.run("uname -a")
            logger.info("Logging platform related details: \n %s \n", linux_ver)

        try:
            os.chdir(tgen.logdir)

            # # Creating router named dir and empty zebra.conf bgpd.conf files
            # # inside the current directory
            # if os.path.isdir("{}".format(rname)):
            #     os.system("rm -rf {}".format(rname))
            #     os.mkdir("{}".format(rname))
            #     os.system("chmod -R go+rw {}".format(rname))
            #     os.chdir("{}/{}".format(tgen.logdir, rname))
            #     os.system("touch zebra.conf bgpd.conf")
            # else:
            #     os.mkdir("{}".format(rname))
            #     os.system("chmod -R go+rw {}".format(rname))
            #     os.chdir("{}/{}".format(tgen.logdir, rname))
            #     os.system("touch zebra.conf bgpd.conf")

        except IOError as err:
            logger.error("I/O error({0}): {1}".format(err.errno, err.strerror))

        topo = tgen.json_topo
        feature = set()

        if "feature" in topo:
            feature.update(topo["feature"])

        if rname in topo["routers"]:
            for key in topo["routers"][rname].keys():
                feature.add(key)

            for val in topo["routers"][rname]["links"].values():
                if "pim" in val:
                    feature.add("pim")
                    break
            for val in topo["routers"][rname]["links"].values():
                if "pim6" in val:
                    feature.add("pim6")
                    break
            for val in topo["routers"][rname]["links"].values():
                if "ospf6" in val:
                    feature.add("ospf6")
                    break
        if "switches" in topo and rname in topo["switches"]:
            for val in topo["switches"][rname]["links"].values():
                if "ospf" in val:
                    feature.add("ospf")
                    break
                if "ospf6" in val:
                    feature.add("ospf6")
                    break

        # Loading empty mgmtd.conf file to router, to start the mgmtd daemon
        router.load_config(
            TopoRouter.RD_MGMTD, "{}/{}/mgmtd.conf".format(tgen.logdir, rname)
        )

        # Loading empty zebra.conf file to router, to start the zebra deamon
        router.load_config(
            TopoRouter.RD_ZEBRA, "{}/{}/zebra.conf".format(tgen.logdir, rname)
        )

        # Loading empty bgpd.conf file to router, to start the bgp deamon
        if "bgp" in feature:
            router.load_config(
                TopoRouter.RD_BGP, "{}/{}/bgpd.conf".format(tgen.logdir, rname)
            )

        # Loading empty pimd.conf file to router, to start the pim deamon
        if "pim" in feature:
            router.load_config(
                TopoRouter.RD_PIM, "{}/{}/pimd.conf".format(tgen.logdir, rname)
            )

        # Loading empty pimd.conf file to router, to start the pim deamon
        if "pim6" in feature:
            router.load_config(
                TopoRouter.RD_PIM6, "{}/{}/pim6d.conf".format(tgen.logdir, rname)
            )

        if "ospf" in feature:
            # Loading empty ospf.conf file to router, to start the ospf deamon
            router.load_config(
                TopoRouter.RD_OSPF, "{}/{}/ospfd.conf".format(tgen.logdir, rname)
            )

        if "ospf6" in feature:
            # Loading empty ospf.conf file to router, to start the ospf deamon
            router.load_config(
                TopoRouter.RD_OSPF6, "{}/{}/ospf6d.conf".format(tgen.logdir, rname)
            )

    # Starting routers
    logger.info("Starting all routers once topology is created")
    tgen.start_router()


def stop_router(tgen, router):
    """
    Router"s current config would be saved to /tmp/topotest/<suite>/<router> for each daemon
    and router and its daemons would be stopped.

    * `tgen`  : topogen object
    * `router`: Device under test
    """

    router_list = tgen.routers()

    # Saving router config to /etc/frr, which will be loaded to router
    # when it starts
    router_list[router].vtysh_cmd("write memory")

    # Stop router
    router_list[router].stop()


def start_router(tgen, router):
    """
    Router will be started and config would be loaded from /tmp/topotest/<suite>/<router> for each
    daemon

    * `tgen`  : topogen object
    * `router`: Device under test
    """

    logger.debug("Entering lib API: start_router")

    try:
        router_list = tgen.routers()

        # Router and its daemons would be started and config would
        #  be loaded to router for each daemon from /etc/frr
        router_list[router].start()

        # Waiting for router to come up
        sleep(5)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: start_router()")
    return True


def number_to_row(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = row 0, a1 = row 1, b2 = row 2, z23 = row 23
    etc
    """
    return int(routerName[1:])


def number_to_column(routerName):
    """
    Returns the number for the router.
    Calculation based on name a0 = columnn 0, a1 = column 0, b2= column 1,
    z23 = column 26 etc
    """
    return ord(routerName[0]) - 97


def topo_daemons(tgen, topo=None):
    """
    Returns daemon list required for the suite based on topojson.
    """
    daemon_list = []

    if topo is None:
        topo = tgen.json_topo

    router_list = tgen.routers()
    routers_sorted = sorted(
        router_list.keys(), key=lambda x: int(re_search("[0-9]+", x).group(0))
    )

    for rtr in routers_sorted:
        if "ospf" in topo["routers"][rtr] and "ospfd" not in daemon_list:
            daemon_list.append("ospfd")

        if "ospf6" in topo["routers"][rtr] and "ospf6d" not in daemon_list:
            daemon_list.append("ospf6d")

        for val in topo["routers"][rtr]["links"].values():
            if "pim" in val and "pimd" not in daemon_list:
                daemon_list.append("pimd")
            if "pim6" in val and "pim6d" not in daemon_list:
                daemon_list.append("pim6d")
            if "ospf" in val and "ospfd" not in daemon_list:
                daemon_list.append("ospfd")
            if "ospf6" in val and "ospf6d" not in daemon_list:
                daemon_list.append("ospf6d")
                break

    return daemon_list


def add_interfaces_to_vlan(tgen, input_dict):
    """
    Add interfaces to VLAN, we need vlan pakcage to be installed on machine

    * `tgen`: tgen onject
    * `input_dict` : interfaces to be added to vlans

    input_dict= {
        "r1":{
            "vlan":{
                VLAN_1: [{
                    intf_r1_s1: {
                        "ip": "10.1.1.1",
                        "subnet": "255.255.255.0
                    }
                }]
            }
        }
    }

    add_interfaces_to_vlan(tgen, input_dict)

    """

    router_list = tgen.routers()
    for dut in input_dict.keys():
        rnode = router_list[dut]

        if "vlan" in input_dict[dut]:
            for vlan, interfaces in input_dict[dut]["vlan"].items():
                for intf_dict in interfaces:
                    for interface, data in intf_dict.items():
                        # Adding interface to VLAN
                        vlan_intf = "{}.{}".format(interface, vlan)
                        cmd = "ip link add link {} name {} type vlan id {}".format(
                            interface, vlan_intf, vlan
                        )
                        logger.info("[DUT: %s]: Running command: %s", dut, cmd)
                        result = rnode.run(cmd)
                        logger.info("result %s", result)

                        # Bringing interface up
                        cmd = "ip link set {} up".format(vlan_intf)
                        logger.info("[DUT: %s]: Running command: %s", dut, cmd)
                        result = rnode.run(cmd)
                        logger.info("result %s", result)

                        # Assigning IP address
                        ifaddr = ipaddress.ip_interface(
                            "{}/{}".format(
                                frr_unicode(data["ip"]), frr_unicode(data["subnet"])
                            )
                        )

                        cmd = "ip -{0} a flush {1} scope global && ip a add {2} dev {1} && ip l set {1} up".format(
                            ifaddr.version, vlan_intf, ifaddr
                        )
                        logger.info("[DUT: %s]: Running command: %s", dut, cmd)
                        result = rnode.run(cmd)
                        logger.info("result %s", result)


def tcpdump_capture_start(
    tgen,
    router,
    intf,
    protocol=None,
    grepstr=None,
    timeout=0,
    options=None,
    cap_file=None,
    background=True,
):
    """
    API to capture network packets using tcp dump.

    Packages used :

    Parameters
    ----------
    * `tgen`: topogen object.
    * `router`: router on which ping has to be performed.
    * `intf` : interface for capture.
    * `protocol` : protocol for which packet needs to be captured.
    * `grepstr` : string to filter out tcp dump output.
    * `timeout` : Time for which packet needs to be captured.
    * `options` : options for TCP dump, all tcpdump options can be used.
    * `cap_file` : filename to store capture dump.
    * `background` : Make tcp dump run in back ground.

    Usage
    -----
    tcpdump_result = tcpdump_dut(tgen, 'r2', intf, protocol='tcp', timeout=20,
        options='-A -vv -x  > r2bgp.txt ')
    Returns
    -------
    1) True for successful capture
    2) errormsg - when tcp dump fails
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.gears[router]

    if timeout > 0:
        cmd = "timeout {}".format(timeout)
    else:
        cmd = ""

    cmdargs = "{} tcpdump".format(cmd)

    if intf:
        cmdargs += " -i {}".format(str(intf))
    if protocol:
        cmdargs += " {}".format(str(protocol))
    if options:
        cmdargs += " -s 0 {}".format(str(options))

    if cap_file:
        file_name = os.path.join(tgen.logdir, router, cap_file)
        cmdargs += " -w {}".format(str(file_name))
        # Remove existing capture file
        rnode.run("rm -rf {}".format(file_name))

    if grepstr:
        cmdargs += ' | grep "{}"'.format(str(grepstr))

    logger.info("Running tcpdump command: [%s]", cmdargs)
    if not background:
        rnode.run(cmdargs)
    else:
        # XXX this & is bogus doesn't work
        # rnode.run("nohup {} & /dev/null 2>&1".format(cmdargs))
        rnode.run("nohup {} > /dev/null 2>&1".format(cmdargs))

    # Check if tcpdump process is running
    if background:
        result = rnode.run("pgrep tcpdump")
        logger.debug("ps -ef | grep tcpdump \n {}".format(result))

        if not result:
            errormsg = "tcpdump is not running {}".format("tcpdump")
            return errormsg
        else:
            logger.info("Packet capture started on %s: interface %s", router, intf)

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def tcpdump_capture_stop(tgen, router):
    """
    API to capture network packets using tcp dump.

    Packages used :

    Parameters
    ----------
    * `tgen`: topogen object.
    * `router`: router on which ping has to be performed.
    * `intf` : interface for capture.
    * `protocol` : protocol for which packet needs to be captured.
    * `grepstr` : string to filter out tcp dump output.
    * `timeout` : Time for which packet needs to be captured.
    * `options` : options for TCP dump, all tcpdump options can be used.
    * `cap2file` : filename to store capture dump.
    * `bakgrnd` : Make tcp dump run in back ground.

    Usage
    -----
    tcpdump_result = tcpdump_dut(tgen, 'r2', intf, protocol='tcp', timeout=20,
        options='-A -vv -x  > r2bgp.txt ')
    Returns
    -------
    1) True for successful capture
    2) errormsg - when tcp dump fails
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.gears[router]

    # Check if tcpdump process is running
    result = rnode.run("ps -ef | grep tcpdump")
    logger.debug("ps -ef | grep tcpdump \n {}".format(result))

    if not re_search(r"{}".format("tcpdump"), result):
        errormsg = "tcpdump is not running {}".format("tcpdump")
        return errormsg
    else:
        # XXX this doesn't work with micronet
        ppid = tgen.net.nameToNode[rnode.name].pid
        rnode.run("set +m; pkill -P %s tcpdump &> /dev/null" % ppid)
        logger.info("Stopped tcpdump capture")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def create_debug_log_config(tgen, input_dict, build=False):
    """
    Enable/disable debug logs for any protocol with defined debug
    options and logs would be saved to created log file

    Parameters
    ----------
    * `tgen` : Topogen object
    * `input_dict` : details to enable debug logs for protocols
    * `build` : Only for initial setup phase this is set as True.


    Usage:
    ------
     input_dict = {
        "r2": {
            "debug":{
                "log_file" : "debug.log",
                "enable": ["pimd", "zebra"],
                "disable": {
                    "bgpd":[
                        'debug bgp neighbor-events',
                        'debug bgp updates',
                        'debug bgp zebra',
                    ]
                }
            }
        }
    }

    result = create_debug_log_config(tgen, input_dict)

    Returns
    -------
    True or False
    """

    result = False
    try:
        debug_config_dict = {}

        for router in input_dict.keys():
            debug_config = []
            if "debug" in input_dict[router]:
                debug_dict = input_dict[router]["debug"]

                disable_logs = debug_dict.setdefault("disable", None)
                enable_logs = debug_dict.setdefault("enable", None)
                log_file = debug_dict.setdefault("log_file", None)

                if log_file:
                    _log_file = os.path.join(tgen.logdir, log_file)
                    debug_config.append("log file {} \n".format(_log_file))

                if type(enable_logs) is list:
                    for daemon in enable_logs:
                        for debug_log in DEBUG_LOGS[daemon]:
                            debug_config.append("{}".format(debug_log))
                elif type(enable_logs) is dict:
                    for daemon, debug_logs in enable_logs.items():
                        for debug_log in debug_logs:
                            debug_config.append("{}".format(debug_log))

                if type(disable_logs) is list:
                    for daemon in disable_logs:
                        for debug_log in DEBUG_LOGS[daemon]:
                            debug_config.append("no {}".format(debug_log))
                elif type(disable_logs) is dict:
                    for daemon, debug_logs in disable_logs.items():
                        for debug_log in debug_logs:
                            debug_config.append("no {}".format(debug_log))
            if debug_config:
                debug_config_dict[router] = debug_config

        result = create_common_configurations(
            tgen, debug_config_dict, "debug_log_config", build=build
        )
    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


#############################################
# Common APIs, will be used by all protocols
#############################################


def create_vrf_cfg(tgen, topo, input_dict=None, build=False):
    """
    Create vrf configuration for created topology. VRF
    configuration is provided in input json file.

    VRF config is done in Linux Kernel:
    * Create VRF
    * Attach interface to VRF
    * Bring up VRF

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring
                     from testcase
    * `build` : Only for initial setup phase this is set as True.

    Usage
    -----
    input_dict={
        "r3": {
            "links": {
                "r2-link1": {"ipv4": "auto", "ipv6": "auto", "vrf": "RED_A"},
                "r2-link2": {"ipv4": "auto", "ipv6": "auto", "vrf": "RED_B"},
                "r2-link3": {"ipv4": "auto", "ipv6": "auto", "vrf": "BLUE_A"},
                "r2-link4": {"ipv4": "auto", "ipv6": "auto", "vrf": "BLUE_B"},
            },
            "vrfs":[
                {
                    "name": "RED_A",
                    "id": "1"
                },
                {
                    "name": "RED_B",
                    "id": "2"
                },
                {
                    "name": "BLUE_A",
                    "id": "3",
                    "delete": True
                },
                {
                    "name": "BLUE_B",
                    "id": "4"
                }
            ]
        }
    }
    result = create_vrf_cfg(tgen, topo, input_dict)

    Returns
    -------
    True or False
    """
    result = True
    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        input_dict = deepcopy(input_dict)

    try:
        config_data_dict = {}

        for c_router, c_data in input_dict.items():
            rnode = tgen.gears[c_router]
            config_data = []
            if "vrfs" in c_data:
                for vrf in c_data["vrfs"]:
                    name = vrf.setdefault("name", None)
                    table_id = vrf.setdefault("id", None)
                    del_action = vrf.setdefault("delete", False)

                    if del_action:
                        # Kernel cmd- Add VRF and table
                        cmd = "ip link del {} type vrf table {}".format(
                            vrf["name"], vrf["id"]
                        )

                        logger.info("[DUT: %s]: Running kernel cmd [%s]", c_router, cmd)
                        rnode.run(cmd)

                        # Kernel cmd - Bring down VRF
                        cmd = "ip link set dev {} down".format(name)
                        logger.info("[DUT: %s]: Running kernel cmd [%s]", c_router, cmd)
                        rnode.run(cmd)

                    else:
                        if name and table_id:
                            # Kernel cmd- Add VRF and table
                            cmd = "ip link add {} type vrf table {}".format(
                                name, table_id
                            )
                            logger.info(
                                "[DUT: %s]: Running kernel cmd " "[%s]", c_router, cmd
                            )
                            rnode.run(cmd)

                            # Kernel cmd - Bring up VRF
                            cmd = "ip link set dev {} up".format(name)
                            logger.info(
                                "[DUT: %s]: Running kernel " "cmd [%s]", c_router, cmd
                            )
                            rnode.run(cmd)

                for vrf in c_data["vrfs"]:
                    vni = vrf.setdefault("vni", None)
                    del_vni = vrf.setdefault("no_vni", None)

                    if "links" in c_data:
                        for destRouterLink, data in sorted(c_data["links"].items()):
                            # Loopback interfaces
                            if "type" in data and data["type"] == "loopback":
                                interface_name = destRouterLink
                            else:
                                interface_name = data["interface"]

                            if "vrf" in data:
                                vrf_list = data["vrf"]

                                if type(vrf_list) is not list:
                                    vrf_list = [vrf_list]

                                for _vrf in vrf_list:
                                    cmd = "ip link set {} master {}".format(
                                        interface_name, _vrf
                                    )

                                    logger.info(
                                        "[DUT: %s]: Running" " kernel cmd [%s]",
                                        c_router,
                                        cmd,
                                    )
                                    rnode.run(cmd)

                    if vni:
                        config_data.append("vrf {}".format(vrf["name"]))
                        cmd = "vni {}".format(vni)
                        config_data.append(cmd)

                    if del_vni:
                        config_data.append("vrf {}".format(vrf["name"]))
                        cmd = "no vni {}".format(del_vni)
                        config_data.append(cmd)

            if config_data:
                config_data_dict[c_router] = config_data

        result = create_common_configurations(
            tgen, config_data_dict, "vrf", build=build
        )

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return result


def create_interface_in_kernel(
    tgen, dut, name, ip_addr, vrf=None, netmask=None, create=True
):
    """
    Cretae interfaces in kernel for ipv4/ipv6
    Config is done in Linux Kernel:

    Parameters
    ----------
    * `tgen` : Topogen object
    * `dut` : Device for which interfaces to be added
    * `name` : interface name
    * `ip_addr` : ip address for interface
    * `vrf` : VRF name, to which interface will be associated
    * `netmask` : netmask value, default is None
    * `create`: Create interface in kernel, if created then no need
                to create
    """

    rnode = tgen.gears[dut]

    if create:
        cmd = "ip link show {0} >/dev/null || ip link add {0} type dummy".format(name)
        rnode.run(cmd)

    if not netmask:
        ifaddr = ipaddress.ip_interface(frr_unicode(ip_addr))
    else:
        ifaddr = ipaddress.ip_interface(
            "{}/{}".format(frr_unicode(ip_addr), frr_unicode(netmask))
        )
    cmd = "ip -{0} a flush {1} scope global && ip a add {2} dev {1} && ip l set {1} up".format(
        ifaddr.version, name, ifaddr
    )
    logger.info("[DUT: %s]: Running command: %s", dut, cmd)
    rnode.run(cmd)

    if vrf:
        cmd = "ip link set {} master {}".format(name, vrf)
        rnode.run(cmd)


def shutdown_bringup_interface_in_kernel(tgen, dut, intf_name, ifaceaction=False):
    """
    Cretae interfaces in kernel for ipv4/ipv6
    Config is done in Linux Kernel:

    Parameters
    ----------
    * `tgen` : Topogen object
    * `dut` : Device for which interfaces to be added
    * `intf_name` : interface name
    * `ifaceaction` : False to shutdown and True to bringup the
                      ineterface
    """

    rnode = tgen.gears[dut]

    cmd = "ip link set dev"
    if ifaceaction:
        action = "up"
        cmd = "{} {} {}".format(cmd, intf_name, action)
    else:
        action = "down"
        cmd = "{} {} {}".format(cmd, intf_name, action)

    logger.info("[DUT: %s]: Running command: %s", dut, cmd)
    rnode.run(cmd)


def validate_ip_address(ip_address):
    """
    Validates the type of ip address
    Parameters
    ----------
    * `ip_address`: IPv4/IPv6 address
    Returns
    -------
    Type of address as string
    """

    if "/" in ip_address:
        ip_address = ip_address.split("/")[0]

    v4 = True
    v6 = True
    try:
        socket.inet_aton(ip_address)
    except socket.error as error:
        logger.debug("Not a valid IPv4 address")
        v4 = False
    else:
        return "ipv4"

    try:
        socket.inet_pton(socket.AF_INET6, ip_address)
    except socket.error as error:
        logger.debug("Not a valid IPv6 address")
        v6 = False
    else:
        return "ipv6"

    if not v4 and not v6:
        raise Exception(
            "InvalidIpAddr", "%s is neither valid IPv4 or IPv6" " address" % ip_address
        )


def check_address_types(addr_type=None):
    """
    Checks environment variable set and compares with the current address type
    """

    addr_types_env = os.environ.get("ADDRESS_TYPES")
    if not addr_types_env:
        addr_types_env = "dual"

    if addr_types_env == "dual":
        addr_types = ["ipv4", "ipv6"]
    elif addr_types_env == "ipv4":
        addr_types = ["ipv4"]
    elif addr_types_env == "ipv6":
        addr_types = ["ipv6"]

    if addr_type is None:
        return addr_types

    if addr_type not in addr_types:
        logger.debug(
            "{} not in supported/configured address types {}".format(
                addr_type, addr_types
            )
        )
        return False

    return True


def generate_ips(network, no_of_ips):
    """
    Returns list of IPs.
    based on start_ip and no_of_ips

    * `network`  : from here the ip will start generating,
                   start_ip will be
    * `no_of_ips` : these many IPs will be generated
    """
    ipaddress_list = []
    if type(network) is not list:
        network = [network]

    for start_ipaddr in network:
        if "/" in start_ipaddr:
            start_ip = start_ipaddr.split("/")[0]
            mask = int(start_ipaddr.split("/")[1])
        else:
            logger.debug("start_ipaddr {} must have a / in it".format(start_ipaddr))
            assert 0

        addr_type = validate_ip_address(start_ip)
        if addr_type == "ipv4":
            if start_ip == "0.0.0.0" and mask == 0 and no_of_ips == 1:
                ipaddress_list.append("{}/{}".format(start_ip, mask))
                return ipaddress_list
            start_ip = ipaddress.IPv4Address(frr_unicode(start_ip))
            step = 2 ** (32 - mask)
        elif addr_type == "ipv6":
            if start_ip == "0::0" and mask == 0 and no_of_ips == 1:
                ipaddress_list.append("{}/{}".format(start_ip, mask))
                return ipaddress_list
            start_ip = ipaddress.IPv6Address(frr_unicode(start_ip))
            step = 2 ** (128 - mask)
        else:
            return []

        next_ip = start_ip
        count = 0
        while count < no_of_ips:
            ipaddress_list.append("{}/{}".format(next_ip, mask))
            if addr_type == "ipv6":
                next_ip = ipaddress.IPv6Address(int(next_ip) + step)
            else:
                next_ip += step
            count += 1

    return ipaddress_list


def find_interface_with_greater_ip(topo, router, loopback=True, interface=True):
    """
    Returns highest interface ip for ipv4/ipv6. If loopback is there then
    it will return highest IP from loopback IPs otherwise from physical
    interface IPs.
    * `topo`  : json file data
    * `router` : router for which highest interface should be calculated
    """

    link_data = topo["routers"][router]["links"]
    lo_list = []
    interfaces_list = []
    lo_exists = False
    for destRouterLink, data in sorted(link_data.items()):
        if loopback:
            if "type" in data and data["type"] == "loopback":
                lo_exists = True
                ip_address = topo["routers"][router]["links"][destRouterLink][
                    "ipv4"
                ].split("/")[0]
                lo_list.append(ip_address)
        if interface:
            ip_address = topo["routers"][router]["links"][destRouterLink]["ipv4"].split(
                "/"
            )[0]
            interfaces_list.append(ip_address)

    if lo_exists:
        return sorted(lo_list)[-1]

    return sorted(interfaces_list)[-1]


def write_test_header(tc_name):
    """Display message at beginning of test case"""
    count = 20
    logger.info("*" * (len(tc_name) + count))
    step("START -> Testcase : %s" % tc_name, reset=True)
    logger.info("*" * (len(tc_name) + count))


def write_test_footer(tc_name):
    """Display message at end of test case"""
    count = 21
    logger.info("=" * (len(tc_name) + count))
    logger.info("Testcase : %s -> PASSED", tc_name)
    logger.info("=" * (len(tc_name) + count))


def interface_status(tgen, topo, input_dict):
    """
    Delete ip route maps from device
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` :  for which router, route map has to be deleted
    Usage
    -----
    input_dict = {
        "r3": {
            "interface_list": ['eth1-r1-r2', 'eth2-r1-r3'],
            "status": "down"
        }
    }
    Returns
    -------
    errormsg(str) or True
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        rlist = []

        for router in input_dict.keys():

            interface_list = input_dict[router]["interface_list"]
            status = input_dict[router].setdefault("status", "up")
            for intf in interface_list:
                rnode = tgen.gears[router]
                interface_set_status(rnode, intf, status)

            rlist.append(router)

        # Load config to routers
        load_config_to_routers(tgen, rlist)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def retry(retry_timeout, initial_wait=0, expected=True, diag_pct=0.75):
    """
    Fixture: Retries function while it's return value is an errormsg (str), False, or it raises an exception.

    * `retry_timeout`: Retry for at least this many seconds; after waiting initial_wait seconds
    * `initial_wait`: Sleeps for this many seconds before first executing function
    * `expected`: if False then the return logic is inverted, except for exceptions,
                      (i.e., a False or errmsg (str) function return ends the retry loop,
                      and returns that False or str value)
    * `diag_pct`: Percentage of `retry_timeout` to keep testing after negative result would have
                  been returned in order to see if a positive result comes after. This is an
                  important diagnostic tool, and normally should not be disabled. Calls to wrapped
                  functions though, can override the `diag_pct` value to make it larger in case more
                  diagnostic retrying is appropriate.
    """

    def _retry(func):
        @wraps(func)
        def func_retry(*args, **kwargs):
            # We will continue to retry diag_pct of the timeout value to see if test would have passed with a
            # longer retry timeout value.
            saved_failure = None

            retry_sleep = 2

            # Allow the wrapped function's args to override the fixtures
            _retry_timeout = kwargs.pop("retry_timeout", retry_timeout)
            _expected = kwargs.pop("expected", expected)
            _initial_wait = kwargs.pop("initial_wait", initial_wait)
            _diag_pct = kwargs.pop("diag_pct", diag_pct)

            start_time = datetime.now()
            retry_until = datetime.now() + timedelta(
                seconds=_retry_timeout + _initial_wait
            )

            if initial_wait > 0:
                logger.info("Waiting for [%s]s as initial delay", initial_wait)
                sleep(initial_wait)

            invert_logic = not _expected
            while True:
                seconds_left = (retry_until - datetime.now()).total_seconds()
                try:
                    ret = func(*args, **kwargs)
                    logger.debug("Function returned %s", ret)

                    negative_result = ret is False or is_string(ret)
                    if negative_result == invert_logic:
                        # Simple case, successful result in time
                        if not saved_failure:
                            return ret

                        # Positive result, but happened after timeout failure, very important to
                        # note for fixing tests.
                        logger.warning(
                            "RETRY DIAGNOSTIC: SUCCEED after FAILED with requested timeout of %.1fs; however, succeeded in %.1fs, investigate timeout timing",
                            _retry_timeout,
                            (datetime.now() - start_time).total_seconds(),
                        )
                        if isinstance(saved_failure, Exception):
                            raise saved_failure  # pylint: disable=E0702
                        return saved_failure

                except Exception as error:
                    logger.info("Function raised exception: %s", str(error))
                    ret = error

                if seconds_left < 0 and saved_failure:
                    logger.info(
                        "RETRY DIAGNOSTIC: Retry timeout reached, still failing"
                    )
                    if isinstance(saved_failure, Exception):
                        raise saved_failure  # pylint: disable=E0702
                    return saved_failure

                if seconds_left < 0:
                    logger.info("Retry timeout of %ds reached", _retry_timeout)

                    saved_failure = ret
                    retry_extra_delta = timedelta(
                        seconds=seconds_left + _retry_timeout * _diag_pct
                    )
                    retry_until = datetime.now() + retry_extra_delta
                    seconds_left = retry_extra_delta.total_seconds()

                    # Generate bundle after setting remaining diagnostic retry time
                    generate_support_bundle()

                    # If user has disabled diagnostic retries return now
                    if not _diag_pct:
                        if isinstance(saved_failure, Exception):
                            raise saved_failure
                        return saved_failure

                if saved_failure:
                    logger.info(
                        "RETRY DIAG: [failure] Sleeping %ds until next retry with %.1f retry time left - too see if timeout was too short",
                        retry_sleep,
                        seconds_left,
                    )
                else:
                    logger.info(
                        "Sleeping %ds until next retry with %.1f retry time left",
                        retry_sleep,
                        seconds_left,
                    )
                sleep(retry_sleep)

        func_retry._original = func
        return func_retry

    return _retry


class Stepper:
    """
    Prints step number for the test case step being executed
    """

    count = 1

    def __call__(self, msg, reset):
        if reset:
            Stepper.count = 1
            logger.info(msg)
        else:
            logger.info("STEP %s: '%s'", Stepper.count, msg)
            Stepper.count += 1


def step(msg, reset=False):
    """
    Call Stepper to print test steps. Need to reset at the beginning of test.
    * ` msg` : Step message body.
    * `reset` : Reset step count to 1 when set to True.
    """
    _step = Stepper()
    _step(msg, reset)


def do_countdown(secs):
    """
    Countdown timer display
    """
    for i in range(secs, 0, -1):
        sys.stdout.write("{} ".format(str(i)))
        sys.stdout.flush()
        sleep(1)
    return


#############################################
# These APIs,  will used by testcase
#############################################
def create_interfaces_cfg(tgen, topo, build=False):
    """
    Create interface configuration for created topology. Basic Interface
    configuration is provided in input json file.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `build` : Only for initial setup phase this is set as True.

    Returns
    -------
    True or False
    """

    def _create_interfaces_ospf_cfg(ospf, c_data, data, ospf_keywords):
        interface_data = []
        ip_ospf = "ipv6 ospf6" if ospf == "ospf6" else "ip ospf"
        for keyword in ospf_keywords:
            if keyword in data[ospf]:
                intf_ospf_value = c_data["links"][destRouterLink][ospf][keyword]
                if "delete" in data and data["delete"]:
                    interface_data.append(
                        "no {} {}".format(ip_ospf, keyword.replace("_", "-"))
                    )
                else:
                    interface_data.append(
                        "{} {} {}".format(
                            ip_ospf, keyword.replace("_", "-"), intf_ospf_value
                        )
                    )
        return interface_data

    result = False
    topo = deepcopy(topo)

    try:
        interface_data_dict = {}

        for c_router, c_data in topo.items():
            interface_data = []
            for destRouterLink, data in sorted(c_data["links"].items()):
                # Loopback interfaces
                if "type" in data and data["type"] == "loopback":
                    interface_name = destRouterLink
                else:
                    interface_name = data["interface"]

                interface_data.append("interface {}".format(str(interface_name)))

                if "ipv4" in data:
                    intf_addr = c_data["links"][destRouterLink]["ipv4"]

                    if "delete" in data and data["delete"]:
                        interface_data.append("no ip address {}".format(intf_addr))
                    else:
                        interface_data.append("ip address {}".format(intf_addr))
                if "ipv6" in data:
                    intf_addr = c_data["links"][destRouterLink]["ipv6"]

                    if "delete" in data and data["delete"]:
                        interface_data.append("no ipv6 address {}".format(intf_addr))
                    else:
                        interface_data.append("ipv6 address {}".format(intf_addr))

                # Wait for vrf interfaces to get link local address once they are up
                if (
                    not destRouterLink == "lo"
                    and "vrf" in topo[c_router]["links"][destRouterLink]
                ):
                    vrf = topo[c_router]["links"][destRouterLink]["vrf"]
                    intf = topo[c_router]["links"][destRouterLink]["interface"]
                    ll = get_frr_ipv6_linklocal(tgen, c_router, intf=intf, vrf=vrf)

                if "ipv6-link-local" in data:
                    intf_addr = c_data["links"][destRouterLink]["ipv6-link-local"]

                    if "delete" in data and data["delete"]:
                        interface_data.append("no ipv6 address {}".format(intf_addr))
                    else:
                        interface_data.append("ipv6 address {}\n".format(intf_addr))

                ospf_keywords = [
                    "hello_interval",
                    "dead_interval",
                    "network",
                    "priority",
                    "cost",
                    "mtu_ignore",
                ]
                if "ospf" in data:
                    interface_data += _create_interfaces_ospf_cfg(
                        "ospf", c_data, data, ospf_keywords + ["area"]
                    )
                if "ospf6" in data:
                    interface_data += _create_interfaces_ospf_cfg(
                        "ospf6", c_data, data, ospf_keywords + ["area"]
                    )
            if interface_data:
                interface_data_dict[c_router] = interface_data

        result = create_common_configurations(
            tgen, interface_data_dict, "interface_config", build=build
        )

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return result


def create_static_routes(tgen, input_dict, build=False):
    """
    Create static routes for given router as defined in input_dict

    Parameters
    ----------
    * `tgen` : Topogen object
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.

    Usage
    -----
    input_dict should be in the format below:
    # static_routes: list of all routes
    # network: network address
    # no_of_ip: number of next-hop address that will be configured
    # admin_distance: admin distance for route/routes.
    # next_hop: starting next-hop address
    # tag: tag id for static routes
    # vrf: VRF name in which static routes needs to be created
    # delete: True if config to be removed. Default False.

    Example:
    "routers": {
        "r1": {
            "static_routes": [
                {
                    "network": "100.0.20.1/32",
                    "no_of_ip": 9,
                    "admin_distance": 100,
                    "next_hop": "10.0.0.1",
                    "tag": 4001,
                    "vrf": "RED_A"
                    "delete": true
                }
            ]
        }
    }

    Returns
    -------
    errormsg(str) or True
    """
    result = False
    logger.debug("Entering lib API: create_static_routes()")
    input_dict = deepcopy(input_dict)

    try:
        static_routes_list_dict = {}

        for router in input_dict.keys():
            if "static_routes" not in input_dict[router]:
                errormsg = "static_routes not present in input_dict"
                logger.info(errormsg)
                continue

            static_routes_list = []

            static_routes = input_dict[router]["static_routes"]
            for static_route in static_routes:
                del_action = static_route.setdefault("delete", False)
                no_of_ip = static_route.setdefault("no_of_ip", 1)
                network = static_route.setdefault("network", [])
                if type(network) is not list:
                    network = [network]

                admin_distance = static_route.setdefault("admin_distance", None)
                tag = static_route.setdefault("tag", None)
                vrf = static_route.setdefault("vrf", None)
                interface = static_route.setdefault("interface", None)
                next_hop = static_route.setdefault("next_hop", None)
                nexthop_vrf = static_route.setdefault("nexthop_vrf", None)

                ip_list = generate_ips(network, no_of_ip)
                for ip in ip_list:
                    addr_type = validate_ip_address(ip)

                    if addr_type == "ipv4":
                        cmd = "ip route {}".format(ip)
                    else:
                        cmd = "ipv6 route {}".format(ip)

                    if interface:
                        cmd = "{} {}".format(cmd, interface)

                    if next_hop:
                        cmd = "{} {}".format(cmd, next_hop)

                    if nexthop_vrf:
                        cmd = "{} nexthop-vrf {}".format(cmd, nexthop_vrf)

                    if vrf:
                        cmd = "{} vrf {}".format(cmd, vrf)

                    if tag:
                        cmd = "{} tag {}".format(cmd, str(tag))

                    if admin_distance:
                        cmd = "{} {}".format(cmd, admin_distance)

                    if del_action:
                        cmd = "no {}".format(cmd)

                    static_routes_list.append(cmd)

            if static_routes_list:
                static_routes_list_dict[router] = static_routes_list

        result = create_common_configurations(
            tgen, static_routes_list_dict, "static_route", build=build
        )

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: create_static_routes()")
    return result


def create_prefix_lists(tgen, input_dict, build=False):
    """
    Create ip prefix lists as per the config provided in input
    JSON or input_dict
    Parameters
    ----------
    * `tgen` : Topogen object
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.
    Usage
    -----
    # pf_lists_1: name of prefix-list, user defined
    # seqid: prefix-list seqid, auto-generated if not given by user
    # network: criteria for applying prefix-list
    # action: permit/deny
    # le: less than or equal number of bits
    # ge: greater than or equal number of bits
    Example
    -------
    input_dict = {
        "r1": {
            "prefix_lists":{
                "ipv4": {
                    "pf_list_1": [
                        {
                            "seqid": 10,
                            "network": "any",
                            "action": "permit",
                            "le": "32",
                            "ge": "30",
                            "delete": True
                        }
                    ]
                }
            }
        }
    }
    Returns
    -------
    errormsg or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False
    try:
        config_data_dict = {}

        for router in input_dict.keys():
            if "prefix_lists" not in input_dict[router]:
                errormsg = "prefix_lists not present in input_dict"
                logger.debug(errormsg)
                continue

            config_data = []
            prefix_lists = input_dict[router]["prefix_lists"]
            for addr_type, prefix_data in prefix_lists.items():
                if not check_address_types(addr_type):
                    continue

                for prefix_name, prefix_list in prefix_data.items():
                    for prefix_dict in prefix_list:
                        if "action" not in prefix_dict or "network" not in prefix_dict:
                            errormsg = "'action' or network' missing in" " input_dict"
                            return errormsg

                        network_addr = prefix_dict["network"]
                        action = prefix_dict["action"]
                        le = prefix_dict.setdefault("le", None)
                        ge = prefix_dict.setdefault("ge", None)
                        seqid = prefix_dict.setdefault("seqid", None)
                        del_action = prefix_dict.setdefault("delete", False)
                        if seqid is None:
                            seqid = get_seq_id("prefix_lists", router, prefix_name)
                        else:
                            set_seq_id("prefix_lists", router, seqid, prefix_name)

                        if addr_type == "ipv4":
                            protocol = "ip"
                        else:
                            protocol = "ipv6"

                        cmd = "{} prefix-list {} seq {} {} {}".format(
                            protocol, prefix_name, seqid, action, network_addr
                        )
                        if le:
                            cmd = "{} le {}".format(cmd, le)
                        if ge:
                            cmd = "{} ge {}".format(cmd, ge)

                        if del_action:
                            cmd = "no {}".format(cmd)

                        config_data.append(cmd)
            if config_data:
                config_data_dict[router] = config_data

        result = create_common_configurations(
            tgen, config_data_dict, "prefix_list", build=build
        )

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def create_route_maps(tgen, input_dict, build=False):
    """
    Create route-map on the devices as per the arguments passed
    Parameters
    ----------
    * `tgen` : Topogen object
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.
    Usage
    -----
    # route_maps: key, value pair for route-map name and its attribute
    # rmap_match_prefix_list_1: user given name for route-map
    # action: PERMIT/DENY
    # match: key,value pair for match criteria. prefix_list, community-list,
             large-community-list or tag. Only one option at a time.
    # prefix_list: name of prefix list
    # large-community-list: name of large community list
    # community-ist: name of community list
    # tag: tag id for static routes
    # set: key, value pair for modifying route attributes
    # localpref: preference value for the network
    # med: metric value advertised for AS
    # aspath: set AS path value
    # weight: weight for the route
    # community: standard community value to be attached
    # large_community: large community value to be attached
    # community_additive: if set to "additive", adds community/large-community
                          value to the existing values of the network prefix
    Example:
    --------
    input_dict = {
        "r1": {
            "route_maps": {
                "rmap_match_prefix_list_1": [
                    {
                        "action": "PERMIT",
                        "match": {
                            "ipv4": {
                                "prefix_list": "pf_list_1"
                            }
                            "ipv6": {
                                "prefix_list": "pf_list_1"
                            }
                            "large-community-list": {
                                "id": "community_1",
                                "exact_match": True
                            }
                            "community_list": {
                                "id": "community_2",
                                "exact_match": True
                            }
                            "tag": "tag_id"
                        },
                        "set": {
                            "locPrf": 150,
                            "metric": 30,
                            "path": {
                                "num": 20000,
                                "action": "prepend",
                            },
                            "weight": 500,
                            "community": {
                                "num": "1:2 2:3",
                                "action": additive
                            }
                            "large_community": {
                                "num": "1:2:3 4:5;6",
                                "action": additive
                            },
                        }
                    }
                ]
            }
        }
    }
    Returns
    -------
    errormsg(str) or True
    """

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    input_dict = deepcopy(input_dict)
    try:
        rmap_data_dict = {}

        for router in input_dict.keys():
            if "route_maps" not in input_dict[router]:
                logger.debug("route_maps not present in input_dict")
                continue
            rmap_data = []
            for rmap_name, rmap_value in input_dict[router]["route_maps"].items():

                for rmap_dict in rmap_value:
                    del_action = rmap_dict.setdefault("delete", False)

                    if del_action:
                        rmap_data.append("no route-map {}".format(rmap_name))
                        continue

                    if "action" not in rmap_dict:
                        errormsg = "action not present in input_dict"
                        logger.error(errormsg)
                        return False

                    rmap_action = rmap_dict.setdefault("action", "deny")

                    seq_id = rmap_dict.setdefault("seq_id", None)
                    if seq_id is None:
                        seq_id = get_seq_id("route_maps", router, rmap_name)
                    else:
                        set_seq_id("route_maps", router, seq_id, rmap_name)

                    rmap_data.append(
                        "route-map {} {} {}".format(rmap_name, rmap_action, seq_id)
                    )

                    if "continue" in rmap_dict:
                        continue_to = rmap_dict["continue"]
                        if continue_to:
                            rmap_data.append("on-match goto {}".format(continue_to))
                        else:
                            logger.error(
                                "In continue, 'route-map entry "
                                "sequence number' is not provided"
                            )
                            return False

                    if "goto" in rmap_dict:
                        go_to = rmap_dict["goto"]
                        if go_to:
                            rmap_data.append("on-match goto {}".format(go_to))
                        else:
                            logger.error(
                                "In goto, 'Goto Clause number' is not" " provided"
                            )
                            return False

                    if "call" in rmap_dict:
                        call_rmap = rmap_dict["call"]
                        if call_rmap:
                            rmap_data.append("call {}".format(call_rmap))
                        else:
                            logger.error(
                                "In call, 'destination Route-Map' is" " not provided"
                            )
                            return False

                    # Verifying if SET criteria is defined
                    if "set" in rmap_dict:
                        set_data = rmap_dict["set"]
                        ipv4_data = set_data.setdefault("ipv4", {})
                        ipv6_data = set_data.setdefault("ipv6", {})
                        local_preference = set_data.setdefault("locPrf", None)
                        metric = set_data.setdefault("metric", None)
                        metric_type = set_data.setdefault("metric-type", None)
                        as_path = set_data.setdefault("path", {})
                        weight = set_data.setdefault("weight", None)
                        community = set_data.setdefault("community", {})
                        large_community = set_data.setdefault("large_community", {})
                        large_comm_list = set_data.setdefault("large_comm_list", {})
                        set_action = set_data.setdefault("set_action", None)
                        nexthop = set_data.setdefault("nexthop", None)
                        origin = set_data.setdefault("origin", None)
                        ext_comm_list = set_data.setdefault("extcommunity", {})
                        metrictype = set_data.setdefault("metric-type", None)

                        # Local Preference
                        if local_preference:
                            rmap_data.append(
                                "set local-preference {}".format(local_preference)
                            )

                        # Metric-Type
                        if metrictype:
                            rmap_data.append("set metric-type {}\n".format(metrictype))

                        # Metric
                        if metric:
                            del_comm = set_data.setdefault("delete", None)
                            if del_comm:
                                rmap_data.append("no set metric {}".format(metric))
                            else:
                                rmap_data.append("set metric {}".format(metric))

                        # Origin
                        if origin:
                            rmap_data.append("set origin {} \n".format(origin))

                        # AS Path Prepend
                        if as_path:
                            as_num = as_path.setdefault("as_num", None)
                            as_action = as_path.setdefault("as_action", None)
                            if as_action and as_num:
                                rmap_data.append(
                                    "set as-path {} {}".format(as_action, as_num)
                                )

                        # Community
                        if community:
                            num = community.setdefault("num", None)
                            comm_action = community.setdefault("action", None)
                            if num:
                                cmd = "set community {}".format(num)
                                if comm_action:
                                    cmd = "{} {}".format(cmd, comm_action)
                                rmap_data.append(cmd)
                            else:
                                logger.error("In community, AS Num not" " provided")
                                return False

                        if large_community:
                            num = large_community.setdefault("num", None)
                            comm_action = large_community.setdefault("action", None)
                            if num:
                                cmd = "set large-community {}".format(num)
                                if comm_action:
                                    cmd = "{} {}".format(cmd, comm_action)

                                rmap_data.append(cmd)
                            else:
                                logger.error(
                                    "In large_community, AS Num not" " provided"
                                )
                                return False
                        if large_comm_list:
                            id = large_comm_list.setdefault("id", None)
                            del_comm = large_comm_list.setdefault("delete", None)
                            if id:
                                cmd = "set large-comm-list {}".format(id)
                                if del_comm:
                                    cmd = "{} delete".format(cmd)

                                rmap_data.append(cmd)
                            else:
                                logger.error("In large_comm_list 'id' not" " provided")
                                return False

                        if ext_comm_list:
                            rt = ext_comm_list.setdefault("rt", None)
                            del_comm = ext_comm_list.setdefault("delete", None)
                            if rt:
                                cmd = "set extcommunity rt {}".format(rt)
                                if del_comm:
                                    cmd = "{} delete".format(cmd)

                                rmap_data.append(cmd)
                            else:
                                logger.debug("In ext_comm_list 'rt' not" " provided")
                                return False

                        # Weight
                        if weight:
                            rmap_data.append("set weight {}".format(weight))
                        if ipv6_data:
                            nexthop = ipv6_data.setdefault("nexthop", None)
                            if nexthop:
                                rmap_data.append("set ipv6 next-hop {}".format(nexthop))

                    # Adding MATCH and SET sequence to RMAP if defined
                    if "match" in rmap_dict:
                        match_data = rmap_dict["match"]
                        ipv4_data = match_data.setdefault("ipv4", {})
                        ipv6_data = match_data.setdefault("ipv6", {})
                        community = match_data.setdefault("community_list", {})
                        large_community = match_data.setdefault("large_community", {})
                        large_community_list = match_data.setdefault(
                            "large_community_list", {}
                        )

                        metric = match_data.setdefault("metric", None)
                        source_vrf = match_data.setdefault("source-vrf", None)

                        if ipv4_data:
                            # fetch prefix list data from rmap
                            prefix_name = ipv4_data.setdefault("prefix_lists", None)
                            if prefix_name:
                                rmap_data.append(
                                    "match ip address"
                                    " prefix-list {}".format(prefix_name)
                                )

                            # fetch tag data from rmap
                            tag = ipv4_data.setdefault("tag", None)
                            if tag:
                                rmap_data.append("match tag {}".format(tag))

                            # fetch large community data from rmap
                            large_community_list = ipv4_data.setdefault(
                                "large_community_list", {}
                            )
                            large_community = match_data.setdefault(
                                "large_community", {}
                            )

                        if ipv6_data:
                            prefix_name = ipv6_data.setdefault("prefix_lists", None)
                            if prefix_name:
                                rmap_data.append(
                                    "match ipv6 address"
                                    " prefix-list {}".format(prefix_name)
                                )

                            # fetch tag data from rmap
                            tag = ipv6_data.setdefault("tag", None)
                            if tag:
                                rmap_data.append("match tag {}".format(tag))

                            # fetch large community data from rmap
                            large_community_list = ipv6_data.setdefault(
                                "large_community_list", {}
                            )
                            large_community = match_data.setdefault(
                                "large_community", {}
                            )

                        if community:
                            if "id" not in community:
                                logger.error(
                                    "'id' is mandatory for "
                                    "community-list in match"
                                    " criteria"
                                )
                                return False
                            cmd = "match community {}".format(community["id"])
                            exact_match = community.setdefault("exact_match", False)
                            if exact_match:
                                cmd = "{} exact-match".format(cmd)

                            rmap_data.append(cmd)
                        if large_community:
                            if "id" not in large_community:
                                logger.error(
                                    "'id' is mandatory for "
                                    "large-community-list in match "
                                    "criteria"
                                )
                                return False
                            cmd = "match large-community {}".format(
                                large_community["id"]
                            )
                            exact_match = large_community.setdefault(
                                "exact_match", False
                            )
                            if exact_match:
                                cmd = "{} exact-match".format(cmd)
                            rmap_data.append(cmd)
                        if large_community_list:
                            if "id" not in large_community_list:
                                logger.error(
                                    "'id' is mandatory for "
                                    "large-community-list in match "
                                    "criteria"
                                )
                                return False
                            cmd = "match large-community {}".format(
                                large_community_list["id"]
                            )
                            exact_match = large_community_list.setdefault(
                                "exact_match", False
                            )
                            if exact_match:
                                cmd = "{} exact-match".format(cmd)
                            rmap_data.append(cmd)

                        if source_vrf:
                            cmd = "match source-vrf {}".format(source_vrf)
                            rmap_data.append(cmd)

                        if metric:
                            cmd = "match metric {}".format(metric)
                            rmap_data.append(cmd)

            if rmap_data:
                rmap_data_dict[router] = rmap_data

        result = create_common_configurations(
            tgen, rmap_data_dict, "route_maps", build=build
        )

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def delete_route_maps(tgen, input_dict):
    """
    Delete ip route maps from device
    * `tgen`  : Topogen object
    * `input_dict` :  for which router,
                      route map has to be deleted
    Usage
    -----
    # Delete route-map rmap_1 and rmap_2 from router r1
    input_dict = {
        "r1": {
            "route_maps": ["rmap_1", "rmap__2"]
        }
    }
    result = delete_route_maps("ipv4", input_dict)
    Returns
    -------
    errormsg(str) or True
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router in input_dict.keys():
        route_maps = input_dict[router]["route_maps"][:]
        rmap_data = input_dict[router]
        rmap_data["route_maps"] = {}
        for route_map_name in route_maps:
            rmap_data["route_maps"].update({route_map_name: [{"delete": True}]})

    return create_route_maps(tgen, input_dict)


def create_bgp_community_lists(tgen, input_dict, build=False):
    """
    Create bgp community-list or large-community-list on the devices as per
    the arguments passed. Takes list of communities in input.
    Parameters
    ----------
    * `tgen` : Topogen object
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.
    Usage
    -----
    input_dict_1 = {
        "r3": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "rmap_lcomm_{}".format(addr_type),
                    "value": "1:1:1 1:2:3 2:1:1 2:2:2",
                    "large": True
                    }
                ]
            }
        }
    }
    result = create_bgp_community_lists(tgen, input_dict_1)
    """

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    input_dict = deepcopy(input_dict)
    try:
        config_data_dict = {}

        for router in input_dict.keys():
            if "bgp_community_lists" not in input_dict[router]:
                errormsg = "bgp_community_lists not present in input_dict"
                logger.debug(errormsg)
                continue

            config_data = []

            community_list = input_dict[router]["bgp_community_lists"]
            for community_dict in community_list:
                del_action = community_dict.setdefault("delete", False)
                community_type = community_dict.setdefault("community_type", None)
                action = community_dict.setdefault("action", None)
                value = community_dict.setdefault("value", "")
                large = community_dict.setdefault("large", None)
                name = community_dict.setdefault("name", None)
                if large:
                    cmd = "bgp large-community-list"
                else:
                    cmd = "bgp community-list"

                if not large and not (community_type and action and value):
                    errormsg = (
                        "community_type, action and value are "
                        "required in bgp_community_list"
                    )
                    logger.error(errormsg)
                    return False

                cmd = "{} {} {} {} {}".format(cmd, community_type, name, action, value)

                if del_action:
                    cmd = "no {}".format(cmd)

                config_data.append(cmd)

            if config_data:
                config_data_dict[router] = config_data

        result = create_common_configurations(
            tgen, config_data_dict, "bgp_community_list", build=build
        )

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def shutdown_bringup_interface(tgen, dut, intf_name, ifaceaction=False):
    """
    Shutdown or bringup router's interface "
    * `tgen`  : Topogen object
    * `dut`  : Device under test
    * `intf_name`  : Interface name to be shut/no shut
    * `ifaceaction` :  Action, to shut/no shut interface,
                       by default is False
    Usage
    -----
    dut = "r3"
    intf = "r3-r1-eth0"
    # Shut down interface
    shutdown_bringup_interface(tgen, dut, intf, False)
    # Bring up interface
    shutdown_bringup_interface(tgen, dut, intf, True)
    Returns
    -------
    errormsg(str) or True
    """

    router_list = tgen.routers()
    if ifaceaction:
        logger.info("Bringing up interface {} : {}".format(dut, intf_name))
    else:
        logger.info("Shutting down interface {} : {}".format(dut, intf_name))

    interface_set_status(router_list[dut], intf_name, ifaceaction)


def addKernelRoute(
    tgen, router, intf, group_addr_range, next_hop=None, src=None, del_action=None
):
    """
    Add route to kernel

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `router`: router for which kernel routes needs to be added
    * `intf`: interface name, for which kernel routes needs to be added
    * `bindToAddress`: bind to <host>, an interface or multicast
                       address

    returns:
    --------
    errormsg or True
    """

    logger.debug("Entering lib API: addKernelRoute()")

    rnode = tgen.gears[router]

    if type(group_addr_range) is not list:
        group_addr_range = [group_addr_range]

    for grp_addr in group_addr_range:

        addr_type = validate_ip_address(grp_addr)
        if addr_type == "ipv4":
            if next_hop is not None:
                cmd = "ip route add {} via {}".format(grp_addr, next_hop)
            else:
                cmd = "ip route add {} dev {}".format(grp_addr, intf)
            if del_action:
                cmd = "ip route del {}".format(grp_addr)
            verify_cmd = "ip route"
        elif addr_type == "ipv6":
            if intf and src:
                cmd = "ip -6 route add {} dev {} src {}".format(grp_addr, intf, src)
            else:
                cmd = "ip -6 route add {} via {}".format(grp_addr, next_hop)
            verify_cmd = "ip -6 route"
            if del_action:
                cmd = "ip -6 route del {}".format(grp_addr)

        logger.info("[DUT: {}]: Running command: [{}]".format(router, cmd))
        output = rnode.run(cmd)

        def check_in_kernel(rnode, verify_cmd, grp_addr, router):
            # Verifying if ip route added to kernel
            errormsg = None
            result = rnode.run(verify_cmd)
            logger.debug("{}\n{}".format(verify_cmd, result))
            if "/" in grp_addr:
                ip, mask = grp_addr.split("/")
                if mask == "32" or mask == "128":
                    grp_addr = ip
                else:
                    mask = "32" if addr_type == "ipv4" else "128"

                    if not re_search(r"{}".format(grp_addr), result) and mask != "0":
                        errormsg = (
                            "[DUT: {}]: Kernal route is not added for group"
                            " address {} Config output: {}".format(
                                router, grp_addr, output
                            )
                        )

            return errormsg

        test_func = functools.partial(
            check_in_kernel, rnode, verify_cmd, grp_addr, router
        )
        (result, out) = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assert result, out

    logger.debug("Exiting lib API: addKernelRoute()")
    return True


def configure_vxlan(tgen, input_dict):
    """
    Add and configure vxlan

    * `tgen`: tgen object
    * `input_dict` : data for vxlan config

    Usage:
    ------
    input_dict= {
        "dcg2":{
            "vxlan":[{
                "vxlan_name": "vxlan75100",
                "vxlan_id": "75100",
                "dstport": 4789,
                "local_addr": "120.0.0.1",
                "learning": "no",
                "delete": True
            }]
        }
    }

    configure_vxlan(tgen, input_dict)

    Returns:
    -------
    True or errormsg

    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for dut in input_dict.keys():
        rnode = router_list[dut]

        if "vxlan" in input_dict[dut]:
            for vxlan_dict in input_dict[dut]["vxlan"]:
                cmd = "ip link "

                del_vxlan = vxlan_dict.setdefault("delete", None)
                vxlan_names = vxlan_dict.setdefault("vxlan_name", [])
                vxlan_ids = vxlan_dict.setdefault("vxlan_id", [])
                dstport = vxlan_dict.setdefault("dstport", None)
                local_addr = vxlan_dict.setdefault("local_addr", None)
                learning = vxlan_dict.setdefault("learning", None)

                config_data = []
                if vxlan_names and vxlan_ids:
                    for vxlan_name, vxlan_id in zip(vxlan_names, vxlan_ids):
                        cmd = "ip link"

                        if del_vxlan:
                            cmd = "{} del {} type vxlan id {}".format(
                                cmd, vxlan_name, vxlan_id
                            )
                        else:
                            cmd = "{} add {} type vxlan id {}".format(
                                cmd, vxlan_name, vxlan_id
                            )

                        if dstport:
                            cmd = "{} dstport {}".format(cmd, dstport)

                        if local_addr:
                            ip_cmd = "ip addr add {} dev {}".format(
                                local_addr, vxlan_name
                            )
                            if del_vxlan:
                                ip_cmd = "ip addr del {} dev {}".format(
                                    local_addr, vxlan_name
                                )

                            config_data.append(ip_cmd)

                            cmd = "{} local {}".format(cmd, local_addr)

                        if learning == "no":
                            cmd = "{} nolearning".format(cmd)

                        elif learning == "yes":
                            cmd = "{} learning".format(cmd)

                        config_data.append(cmd)

                        try:
                            for _cmd in config_data:
                                logger.info("[DUT: %s]: Running command: %s", dut, _cmd)
                                rnode.run(_cmd)

                        except InvalidCLIError:
                            # Traceback
                            errormsg = traceback.format_exc()
                            logger.error(errormsg)
                            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


def configure_brctl(tgen, topo, input_dict):
    """
    Add and configure brctl

    * `tgen`: tgen object
    * `input_dict` : data for brctl config

    Usage:
    ------
    input_dict= {
        dut:{
            "brctl": [{
                        "brctl_name": "br100",
                        "addvxlan": "vxlan75100",
                        "vrf": "RED",
                        "stp": "off"
            }]
        }
    }

    configure_brctl(tgen, topo, input_dict)

    Returns:
    -------
    True or errormsg

    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for dut in input_dict.keys():
        rnode = router_list[dut]

        if "brctl" in input_dict[dut]:
            for brctl_dict in input_dict[dut]["brctl"]:

                brctl_names = brctl_dict.setdefault("brctl_name", [])
                addvxlans = brctl_dict.setdefault("addvxlan", [])
                stp_values = brctl_dict.setdefault("stp", [])
                vrfs = brctl_dict.setdefault("vrf", [])

                ip_cmd = "ip link set"
                for brctl_name, vxlan, vrf, stp in zip(
                    brctl_names, addvxlans, vrfs, stp_values
                ):

                    ip_cmd_list = []
                    cmd = "ip link add name {} type bridge stp_state {}".format(
                        brctl_name, stp
                    )

                    logger.info("[DUT: %s]: Running command: %s", dut, cmd)
                    rnode.run(cmd)

                    ip_cmd_list.append("{} up dev {}".format(ip_cmd, brctl_name))

                    if vxlan:
                        cmd = "{} dev {} master {}".format(ip_cmd, vxlan, brctl_name)

                        logger.info("[DUT: %s]: Running command: %s", dut, cmd)
                        rnode.run(cmd)

                        ip_cmd_list.append("{} up dev {}".format(ip_cmd, vxlan))

                    if vrf:
                        ip_cmd_list.append(
                            "{} dev {} master {}".format(ip_cmd, brctl_name, vrf)
                        )

                        for intf_name, data in topo["routers"][dut]["links"].items():
                            if "vrf" not in data:
                                continue

                            if data["vrf"] == vrf:
                                ip_cmd_list.append(
                                    "{} up dev {}".format(ip_cmd, data["interface"])
                                )

                    try:
                        for _ip_cmd in ip_cmd_list:
                            logger.info("[DUT: %s]: Running command: %s", dut, _ip_cmd)
                            rnode.run(_ip_cmd)

                    except InvalidCLIError:
                        # Traceback
                        errormsg = traceback.format_exc()
                        logger.error(errormsg)
                        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def configure_interface_mac(tgen, input_dict):
    """
    Add and configure brctl

    * `tgen`: tgen object
    * `input_dict` : data for mac config

    input_mac= {
        "edge1":{
                "br75100": "00:80:48:BA:d1:00,
                "br75200": "00:80:48:BA:d1:00
        }
    }

    configure_interface_mac(tgen, input_mac)

    Returns:
    -------
    True or errormsg

    """

    router_list = tgen.routers()
    for dut in input_dict.keys():
        rnode = router_list[dut]

        for intf, mac in input_dict[dut].items():
            cmd = "ip link set {} address {}".format(intf, mac)
            logger.info("[DUT: %s]: Running command: %s", dut, cmd)

            try:
                result = rnode.run(cmd)
                if len(result) != 0:
                    return result

            except InvalidCLIError:
                # Traceback
                errormsg = traceback.format_exc()
                logger.error(errormsg)
                return errormsg

    return True


def socat_send_mld_join(
    tgen,
    server,
    protocol_option,
    mld_groups,
    send_from_intf,
    send_from_intf_ip=None,
    port=12345,
    reuseaddr=True,
):
    """
    API to send MLD join using SOCAT tool

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `server`: iperf server, from where IGMP join would be sent
    * `protocol_option`: Protocol options, ex: UDP6-RECV
    * `mld_groups`: IGMP group for which join has to be sent
    * `send_from_intf`: Interface from which join would be sent
    * `send_from_intf_ip`: Interface IP, default is None
    * `port`: Port to be used, default is 12345
    * `reuseaddr`: True|False, bydefault True

    returns:
    --------
    errormsg or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.routers()[server]
    socat_args = "socat -u "

    # UDP4/TCP4/UDP6/UDP6-RECV/UDP6-SEND
    if protocol_option:
        socat_args += "{}".format(protocol_option)

    if port:
        socat_args += ":{},".format(port)

    if reuseaddr:
        socat_args += "{},".format("reuseaddr")

    # Group address range to cover
    if mld_groups:
        if not isinstance(mld_groups, list):
            mld_groups = [mld_groups]

    for mld_group in mld_groups:
        socat_cmd = socat_args
        join_option = "ipv6-join-group"

        if send_from_intf and not send_from_intf_ip:
            socat_cmd += "{}='[{}]:{}'".format(join_option, mld_group, send_from_intf)
        else:
            socat_cmd += "{}='[{}]:{}:[{}]'".format(
                join_option, mld_group, send_from_intf, send_from_intf_ip
            )

        socat_cmd += " STDOUT"

        socat_cmd += " &>{}/socat.logs &".format(tgen.logdir)

        # Run socat command to send IGMP join
        logger.info("[DUT: {}]: Running command: [{}]".format(server, socat_cmd))
        output = rnode.run("set +m; {} sleep 0.5".format(socat_cmd))

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def socat_send_pim6_traffic(
    tgen,
    server,
    protocol_option,
    mld_groups,
    send_from_intf,
    port=12345,
    multicast_hops=True,
):
    """
    API to send pim6 data taffic using SOCAT tool

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `server`: iperf server, from where IGMP join would be sent
    * `protocol_option`: Protocol options, ex: UDP6-RECV
    * `mld_groups`: MLD group for which join has to be sent
    * `send_from_intf`: Interface from which join would be sent
    * `port`: Port to be used, default is 12345
    * `multicast_hops`: multicast-hops count, default is 255

    returns:
    --------
    errormsg or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.routers()[server]
    socat_args = "socat -u STDIO "

    # UDP4/TCP4/UDP6/UDP6-RECV/UDP6-SEND
    if protocol_option:
        socat_args += "'{}".format(protocol_option)

    # Group address range to cover
    if mld_groups:
        if not isinstance(mld_groups, list):
            mld_groups = [mld_groups]

    for mld_group in mld_groups:
        socat_cmd = socat_args
        if port:
            socat_cmd += ":[{}]:{},".format(mld_group, port)

        if send_from_intf:
            socat_cmd += "interface={0},so-bindtodevice={0},".format(send_from_intf)

        if multicast_hops:
            socat_cmd += "multicast-hops=255'"

        socat_cmd += " &>{}/socat.logs &".format(tgen.logdir)

        # Run socat command to send pim6 traffic
        logger.info(
            "[DUT: {}]: Running command: [set +m; ( while sleep 1; do date; done ) | {}]".format(
                server, socat_cmd
            )
        )

        # Open a shell script file and write data to it, which will be
        # used to send pim6 traffic continously
        traffic_shell_script = "{}/{}/traffic.sh".format(tgen.logdir, server)
        with open("{}".format(traffic_shell_script), "w") as taffic_sh:
            taffic_sh.write(
                "#!/usr/bin/env bash\n( while sleep 1; do date; done ) | {}\n".format(
                    socat_cmd
                )
            )

        rnode.run("chmod 755 {}".format(traffic_shell_script))
        output = rnode.run("{} &> /dev/null".format(traffic_shell_script))

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def kill_socat(tgen, dut=None, action=None):
    """
    Killing socat process if running for any router in topology

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `dut`   : Any iperf hostname to send igmp prune
    * `action`: to kill mld join using socat
                to kill mld traffic using socat

    Usage:
    ------
    kill_socat(tgen, dut ="i6", action="remove_mld_join")

    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router, rnode in router_list.items():
        if dut is not None and router != dut:
            continue

        if action == "remove_mld_join":
            cmd = "ps -ef | grep socat | grep UDP6-RECV | grep {}".format(router)
        elif action == "remove_mld_traffic":
            cmd = "ps -ef | grep socat | grep UDP6-SEND | grep {}".format(router)
        else:
            cmd = "ps -ef | grep socat".format(router)

        awk_cmd = "awk -F' ' '{print $2}' | xargs kill -9 &>/dev/null &"
        cmd = "{} | {}".format(cmd, awk_cmd)

        logger.debug("[DUT: {}]: Running command: [{}]".format(router, cmd))
        rnode.run(cmd)

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))


#############################################
# Verification APIs
#############################################
@retry(retry_timeout=40)
def verify_rib(
    tgen,
    addr_type,
    dut,
    input_dict,
    next_hop=None,
    protocol=None,
    tag=None,
    metric=None,
    fib=None,
    count_only=False,
    admin_distance=None,
):
    """
    Data will be read from input_dict or input JSON file, API will generate
    same prefixes, which were redistributed by either create_static_routes() or
    advertise_networks_using_network_command() and do will verify next_hop and
    each prefix/routes is present in "show ip/ipv6 route {bgp/stataic} json"
    command o/p.

    Parameters
    ----------
    * `tgen` : topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test, for which user wants to test the data
    * `input_dict` : input dict, has details of static routes
    * `next_hop`[optional]: next_hop which needs to be verified,
                           default: static
    * `protocol`[optional]: protocol, default = None
    * `count_only`[optional]: count of nexthops only, not specific addresses,
                              default = False

    Usage
    -----
    # RIB can be verified for static routes OR network advertised using
    network command. Following are input_dicts to create static routes
    and advertise networks using network command. Any one of the input_dict
    can be passed to verify_rib() to verify routes in DUT"s RIB.

    # Creating static routes for r1
    input_dict = {
        "r1": {
            "static_routes": [{"network": "10.0.20.1/32", "no_of_ip": 9, \
        "admin_distance": 100, "next_hop": "10.0.0.2", "tag": 4001}]
        }}
    # Advertising networks using network command in router r1
    input_dict = {
       "r1": {
          "advertise_networks": [{"start_ip": "20.0.0.0/32",
                                  "no_of_network": 10},
                                  {"start_ip": "30.0.0.0/32"}]
        }}
    # Verifying ipv4 routes in router r1 learned via BGP
    dut = "r2"
    protocol = "bgp"
    result = verify_rib(tgen, "ipv4", dut, input_dict, protocol = protocol)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    additional_nexthops_in_required_nhs = []
    found_hops = []
    for routerInput in input_dict.keys():
        for router, rnode in router_list.items():
            if router != dut:
                continue

            logger.info("Checking router %s RIB:", router)

            # Verifying RIB routes
            if addr_type == "ipv4":
                command = "show ip route"
            else:
                command = "show ipv6 route"

            found_routes = []
            missing_routes = []

            if "static_routes" in input_dict[routerInput]:
                static_routes = input_dict[routerInput]["static_routes"]

                for static_route in static_routes:
                    if "vrf" in static_route and static_route["vrf"] is not None:

                        logger.info(
                            "[DUT: {}]: Verifying routes for VRF:"
                            " {}".format(router, static_route["vrf"])
                        )

                        cmd = "{} vrf {}".format(command, static_route["vrf"])

                    else:
                        cmd = "{}".format(command)

                    if protocol:
                        cmd = "{} {}".format(cmd, protocol)

                    cmd = "{} json".format(cmd)

                    rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                    # Verifying output dictionary rib_routes_json is not empty
                    if bool(rib_routes_json) is False:
                        errormsg = "No route found in rib of router {}..".format(router)
                        return errormsg

                    network = static_route["network"]
                    if "no_of_ip" in static_route:
                        no_of_ip = static_route["no_of_ip"]
                    else:
                        no_of_ip = 1

                    if "tag" in static_route:
                        _tag = static_route["tag"]
                    else:
                        _tag = None

                    # Generating IPs for verification
                    ip_list = generate_ips(network, no_of_ip)
                    st_found = False
                    nh_found = False

                    for st_rt in ip_list:
                        st_rt = str(
                            ipaddress.ip_network(frr_unicode(st_rt), strict=False)
                        )
                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != addr_type:
                            continue

                        if st_rt in rib_routes_json:
                            st_found = True
                            found_routes.append(st_rt)

                            if "queued" in rib_routes_json[st_rt][0]:
                                errormsg = "Route {} is queued\n".format(st_rt)
                                return errormsg

                            if fib and next_hop:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]

                                for mnh in range(0, len(rib_routes_json[st_rt])):
                                    if not "selected" in rib_routes_json[st_rt][mnh]:
                                        continue

                                    if (
                                        "fib"
                                        in rib_routes_json[st_rt][mnh]["nexthops"][0]
                                    ):
                                        found_hops.append(
                                            [
                                                rib_r["ip"]
                                                for rib_r in rib_routes_json[st_rt][
                                                    mnh
                                                ]["nexthops"]
                                            ]
                                        )

                                if found_hops[0]:
                                    missing_list_of_nexthops = set(
                                        found_hops[0]
                                    ).difference(next_hop)
                                    additional_nexthops_in_required_nhs = set(
                                        next_hop
                                    ).difference(found_hops[0])

                                    if additional_nexthops_in_required_nhs:
                                        logger.info(
                                            "Nexthop "
                                            "%s is not active for route %s in "
                                            "RIB of router %s\n",
                                            additional_nexthops_in_required_nhs,
                                            st_rt,
                                            dut,
                                        )
                                        errormsg = (
                                            "Nexthop {} is not active"
                                            " for route {} in RIB of router"
                                            " {}\n".format(
                                                additional_nexthops_in_required_nhs,
                                                st_rt,
                                                dut,
                                            )
                                        )
                                        return errormsg
                                    else:
                                        nh_found = True

                            elif next_hop and fib is None:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]
                                found_hops = [
                                    rib_r["ip"]
                                    for rib_r in rib_routes_json[st_rt][0]["nexthops"]
                                    if "ip" in rib_r
                                ]

                                # If somehow key "ip" is not found in nexthops JSON
                                # then found_hops would be 0, this particular
                                # situation will be handled here
                                if not len(found_hops):
                                    errormsg = (
                                        "Nexthop {} is Missing for "
                                        "route {} in RIB of router {}\n".format(
                                            next_hop,
                                            st_rt,
                                            dut,
                                        )
                                    )
                                    return errormsg

                                # Check only the count of nexthops
                                if count_only:
                                    if len(next_hop) == len(found_hops):
                                        nh_found = True
                                    else:
                                        errormsg = (
                                            "Nexthops are missing for "
                                            "route {} in RIB of router {}: "
                                            "expected {}, found {}\n".format(
                                                st_rt,
                                                dut,
                                                len(next_hop),
                                                len(found_hops),
                                            )
                                        )
                                        return errormsg

                                # Check the actual nexthops
                                elif found_hops:
                                    missing_list_of_nexthops = set(
                                        found_hops
                                    ).difference(next_hop)
                                    additional_nexthops_in_required_nhs = set(
                                        next_hop
                                    ).difference(found_hops)

                                    if additional_nexthops_in_required_nhs:
                                        logger.info(
                                            "Missing nexthop %s for route"
                                            " %s in RIB of router %s\n",
                                            additional_nexthops_in_required_nhs,
                                            st_rt,
                                            dut,
                                        )
                                        errormsg = (
                                            "Nexthop {} is Missing for "
                                            "route {} in RIB of router {}\n".format(
                                                additional_nexthops_in_required_nhs,
                                                st_rt,
                                                dut,
                                            )
                                        )
                                        return errormsg
                                    else:
                                        nh_found = True

                            if tag:
                                if "tag" not in rib_routes_json[st_rt][0]:
                                    errormsg = (
                                        "[DUT: {}]: tag is not"
                                        " present for"
                                        " route {} in RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg

                                if _tag != rib_routes_json[st_rt][0]["tag"]:
                                    errormsg = (
                                        "[DUT: {}]: tag value {}"
                                        " is not matched for"
                                        " route {} in RIB \n".format(
                                            dut,
                                            _tag,
                                            st_rt,
                                        )
                                    )
                                    return errormsg

                            if admin_distance is not None:
                                if "distance" not in rib_routes_json[st_rt][0]:
                                    errormsg = (
                                        "[DUT: {}]: admin distance is"
                                        " not present for"
                                        " route {} in RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg

                                if (
                                    admin_distance
                                    != rib_routes_json[st_rt][0]["distance"]
                                ):
                                    errormsg = (
                                        "[DUT: {}]: admin distance value "
                                        "{} is not matched for "
                                        "route {} in RIB \n".format(
                                            dut,
                                            admin_distance,
                                            st_rt,
                                        )
                                    )
                                    return errormsg

                            if metric is not None:
                                if "metric" not in rib_routes_json[st_rt][0]:
                                    errormsg = (
                                        "[DUT: {}]: metric is"
                                        " not present for"
                                        " route {} in RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg

                                if metric != rib_routes_json[st_rt][0]["metric"]:
                                    errormsg = (
                                        "[DUT: {}]: metric value "
                                        "{} is not matched for "
                                        "route {} in RIB \n".format(
                                            dut,
                                            metric,
                                            st_rt,
                                        )
                                    )
                                    return errormsg

                        else:
                            missing_routes.append(st_rt)

                if nh_found:
                    logger.info(
                        "[DUT: {}]: Found next_hop {} for"
                        " RIB routes: {}".format(router, next_hop, found_routes)
                    )

                if len(missing_routes) > 0:
                    errormsg = "[DUT: {}]: Missing route in RIB, " "routes: {}".format(
                        dut, missing_routes
                    )
                    return errormsg

                if found_routes:
                    logger.info(
                        "[DUT: %s]: Verified routes in RIB, found" " routes are: %s\n",
                        dut,
                        found_routes,
                    )

                continue

            if "bgp" in input_dict[routerInput]:
                if (
                    "advertise_networks"
                    not in input_dict[routerInput]["bgp"]["address_family"][addr_type][
                        "unicast"
                    ]
                ):
                    continue

                found_routes = []
                missing_routes = []
                advertise_network = input_dict[routerInput]["bgp"]["address_family"][
                    addr_type
                ]["unicast"]["advertise_networks"]

                # Continue if there are no network advertise
                if len(advertise_network) == 0:
                    continue

                for advertise_network_dict in advertise_network:
                    if "vrf" in advertise_network_dict:
                        cmd = "{} vrf {} json".format(
                            command, advertise_network_dict["vrf"]
                        )
                    else:
                        cmd = "{} json".format(command)

                rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                # Verifying output dictionary rib_routes_json is not empty
                if bool(rib_routes_json) is False:
                    errormsg = "No route found in rib of router {}..".format(router)
                    return errormsg

                start_ip = advertise_network_dict["network"]
                if "no_of_network" in advertise_network_dict:
                    no_of_network = advertise_network_dict["no_of_network"]
                else:
                    no_of_network = 1

                # Generating IPs for verification
                ip_list = generate_ips(start_ip, no_of_network)
                st_found = False
                nh_found = False

                for st_rt in ip_list:
                    st_rt = str(ipaddress.ip_network(frr_unicode(st_rt), strict=False))

                    _addr_type = validate_ip_address(st_rt)
                    if _addr_type != addr_type:
                        continue

                    if st_rt in rib_routes_json:
                        st_found = True
                        found_routes.append(st_rt)

                        if "queued" in rib_routes_json[st_rt][0]:
                            errormsg = "Route {} is queued\n".format(st_rt)
                            return errormsg

                        if next_hop:
                            if type(next_hop) is not list:
                                next_hop = [next_hop]

                            count = 0
                            for nh in next_hop:
                                for nh_dict in rib_routes_json[st_rt][0]["nexthops"]:
                                    if nh_dict["ip"] != nh:
                                        continue
                                    else:
                                        count += 1

                            if count == len(next_hop):
                                nh_found = True
                            else:
                                errormsg = (
                                    "Nexthop {} is Missing"
                                    " for route {} in "
                                    "RIB of router {}\n".format(next_hop, st_rt, dut)
                                )
                                return errormsg
                    else:
                        missing_routes.append(st_rt)

                if nh_found:
                    logger.info(
                        "Found next_hop {} for all routes in RIB"
                        " of router {}\n".format(next_hop, dut)
                    )

                if len(missing_routes) > 0:
                    errormsg = (
                        "Missing {} route in RIB of router {}, "
                        "routes: {} \n".format(addr_type, dut, missing_routes)
                    )
                    return errormsg

                if found_routes:
                    logger.info(
                        "Verified {} routes in router {} RIB, found"
                        " routes  are: {}\n".format(addr_type, dut, found_routes)
                    )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=12)
def verify_fib_routes(tgen, addr_type, dut, input_dict, next_hop=None, protocol=None):
    """
    Data will be read from input_dict or input JSON file, API will generate
    same prefixes, which were redistributed by either create_static_routes() or
    advertise_networks_using_network_command() and will verify next_hop and
    each prefix/routes is present in "show ip/ipv6 fib json"
    command o/p.

    Parameters
    ----------
    * `tgen` : topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test, for which user wants to test the data
    * `input_dict` : input dict, has details of static routes
    * `next_hop`[optional]: next_hop which needs to be verified,
                           default: static

    Usage
    -----
    input_routes_r1 = {
        "r1": {
            "static_routes": [{
                "network": ["1.1.1.1/32],
                "next_hop": "Null0",
                "vrf": "RED"
            }]
        }
    }
    result = result = verify_fib_routes(tgen, "ipv4, "r1", input_routes_r1)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    if dut not in router_list:
        return

    for routerInput in input_dict.keys():
        # XXX replace with router = dut; rnode = router_list[dut]
        for router, rnode in router_list.items():
            if router != dut:
                continue

            logger.info("Checking router %s FIB routes:", router)

            # Verifying RIB routes
            if addr_type == "ipv4":
                command = "show ip fib"
            else:
                command = "show ipv6 fib"

            found_routes = []
            missing_routes = []

            if protocol:
                command = "{} {}".format(command, protocol)

            if "static_routes" in input_dict[routerInput]:
                static_routes = input_dict[routerInput]["static_routes"]

                for static_route in static_routes:
                    if "vrf" in static_route and static_route["vrf"] is not None:

                        logger.info(
                            "[DUT: {}]: Verifying routes for VRF:"
                            " {}".format(router, static_route["vrf"])
                        )

                        cmd = "{} vrf {}".format(command, static_route["vrf"])

                    else:
                        cmd = "{}".format(command)

                    cmd = "{} json".format(cmd)

                    rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                    # Verifying output dictionary rib_routes_json is not empty
                    if bool(rib_routes_json) is False:
                        errormsg = "[DUT: {}]: No route found in fib".format(router)
                        return errormsg

                    network = static_route["network"]
                    if "no_of_ip" in static_route:
                        no_of_ip = static_route["no_of_ip"]
                    else:
                        no_of_ip = 1

                    # Generating IPs for verification
                    ip_list = generate_ips(network, no_of_ip)
                    st_found = False
                    nh_found = False

                    for st_rt in ip_list:
                        st_rt = str(
                            ipaddress.ip_network(frr_unicode(st_rt), strict=False)
                        )
                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != addr_type:
                            continue

                        if st_rt in rib_routes_json:
                            st_found = True
                            found_routes.append(st_rt)

                            if next_hop:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]

                                count = 0
                                for nh in next_hop:
                                    for nh_dict in rib_routes_json[st_rt][0][
                                        "nexthops"
                                    ]:
                                        if nh_dict["ip"] != nh:
                                            continue
                                        else:
                                            count += 1

                                if count == len(next_hop):
                                    nh_found = True
                                else:
                                    missing_routes.append(st_rt)
                                    errormsg = (
                                        "Nexthop {} is Missing"
                                        " for route {} in "
                                        "RIB of router {}\n".format(
                                            next_hop, st_rt, dut
                                        )
                                    )
                                    return errormsg

                        else:
                            missing_routes.append(st_rt)

                if len(missing_routes) > 0:
                    errormsg = "[DUT: {}]: Missing route in FIB:" " {}".format(
                        dut, missing_routes
                    )
                    return errormsg

                if nh_found:
                    logger.info(
                        "Found next_hop {} for all routes in RIB"
                        " of router {}\n".format(next_hop, dut)
                    )

                if found_routes:
                    logger.info(
                        "[DUT: %s]: Verified routes in FIB, found" " routes are: %s\n",
                        dut,
                        found_routes,
                    )

                continue

            if "bgp" in input_dict[routerInput]:
                if (
                    "advertise_networks"
                    not in input_dict[routerInput]["bgp"]["address_family"][addr_type][
                        "unicast"
                    ]
                ):
                    continue

                found_routes = []
                missing_routes = []
                advertise_network = input_dict[routerInput]["bgp"]["address_family"][
                    addr_type
                ]["unicast"]["advertise_networks"]

                # Continue if there are no network advertise
                if len(advertise_network) == 0:
                    continue

                for advertise_network_dict in advertise_network:
                    if "vrf" in advertise_network_dict:
                        cmd = "{} vrf {} json".format(command, static_route["vrf"])
                    else:
                        cmd = "{} json".format(command)

                rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                # Verifying output dictionary rib_routes_json is not empty
                if bool(rib_routes_json) is False:
                    errormsg = "No route found in rib of router {}..".format(router)
                    return errormsg

                start_ip = advertise_network_dict["network"]
                if "no_of_network" in advertise_network_dict:
                    no_of_network = advertise_network_dict["no_of_network"]
                else:
                    no_of_network = 1

                # Generating IPs for verification
                ip_list = generate_ips(start_ip, no_of_network)
                st_found = False
                nh_found = False

                for st_rt in ip_list:
                    st_rt = str(ipaddress.ip_network(frr_unicode(st_rt), strict=False))

                    _addr_type = validate_ip_address(st_rt)
                    if _addr_type != addr_type:
                        continue

                    if st_rt in rib_routes_json:
                        st_found = True
                        found_routes.append(st_rt)

                        if next_hop:
                            if type(next_hop) is not list:
                                next_hop = [next_hop]

                            count = 0
                            for nh in next_hop:
                                for nh_dict in rib_routes_json[st_rt][0]["nexthops"]:
                                    if nh_dict["ip"] != nh:
                                        continue
                                    else:
                                        count += 1

                            if count == len(next_hop):
                                nh_found = True
                            else:
                                missing_routes.append(st_rt)
                                errormsg = (
                                    "Nexthop {} is Missing"
                                    " for route {} in "
                                    "RIB of router {}\n".format(next_hop, st_rt, dut)
                                )
                                return errormsg
                    else:
                        missing_routes.append(st_rt)

                if len(missing_routes) > 0:
                    errormsg = "[DUT: {}]: Missing route in FIB: " "{} \n".format(
                        dut, missing_routes
                    )
                    return errormsg

                if nh_found:
                    logger.info(
                        "Found next_hop {} for all routes in RIB"
                        " of router {}\n".format(next_hop, dut)
                    )

                if found_routes:
                    logger.info(
                        "[DUT: {}]: Verified routes FIB"
                        ", found routes  are: {}\n".format(dut, found_routes)
                    )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def verify_admin_distance_for_static_routes(tgen, input_dict):
    """
    API to verify admin distance for static routes as defined in input_dict/
    input JSON by running show ip/ipv6 route json command.
    Parameter
    ---------
    * `tgen` : topogen object
    * `input_dict`: having details like - for which router and static routes
                    admin dsitance needs to be verified
    Usage
    -----
    # To verify admin distance is 10 for prefix 10.0.20.1/32 having next_hop
    10.0.0.2 in router r1
    input_dict = {
        "r1": {
            "static_routes": [{
                "network": "10.0.20.1/32",
                "admin_distance": 10,
                "next_hop": "10.0.0.2"
            }]
        }
    }
    result = verify_admin_distance_for_static_routes(tgen, input_dict)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router in input_dict.keys():
        if router not in router_list:
            continue
        rnode = router_list[router]

        for static_route in input_dict[router]["static_routes"]:
            addr_type = validate_ip_address(static_route["network"])
            # Command to execute
            if addr_type == "ipv4":
                command = "show ip route json"
            else:
                command = "show ipv6 route json"
            show_ip_route_json = run_frr_cmd(rnode, command, isjson=True)

            logger.info(
                "Verifying admin distance for static route %s" " under dut %s:",
                static_route,
                router,
            )
            network = static_route["network"]
            next_hop = static_route["next_hop"]
            admin_distance = static_route["admin_distance"]
            route_data = show_ip_route_json[network][0]
            if network in show_ip_route_json:
                if route_data["nexthops"][0]["ip"] == next_hop:
                    if route_data["distance"] != admin_distance:
                        errormsg = (
                            "Verification failed: admin distance"
                            " for static route {} under dut {},"
                            " found:{} but expected:{}".format(
                                static_route,
                                router,
                                route_data["distance"],
                                admin_distance,
                            )
                        )
                        return errormsg
                    else:
                        logger.info(
                            "Verification successful: admin"
                            " distance for static route %s under"
                            " dut %s, found:%s",
                            static_route,
                            router,
                            route_data["distance"],
                        )

            else:
                errormsg = (
                    "Static route {} not found in "
                    "show_ip_route_json for dut {}".format(network, router)
                )
                return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def verify_prefix_lists(tgen, input_dict):
    """
    Running "show ip prefix-list" command and verifying given prefix-list
    is present in router.
    Parameters
    ----------
    * `tgen` : topogen object
    * `input_dict`: data to verify prefix lists
    Usage
    -----
    # To verify pf_list_1 is present in router r1
    input_dict = {
        "r1": {
            "prefix_lists": ["pf_list_1"]
        }}
    result = verify_prefix_lists("ipv4", input_dict, tgen)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router in input_dict.keys():
        if router not in router_list:
            continue

        rnode = router_list[router]

        # Show ip prefix list
        show_prefix_list = run_frr_cmd(rnode, "show ip prefix-list")

        # Verify Prefix list is deleted
        prefix_lists_addr = input_dict[router]["prefix_lists"]
        for addr_type in prefix_lists_addr:
            if not check_address_types(addr_type):
                continue
            # show ip prefix list
            if addr_type == "ipv4":
                cmd = "show ip prefix-list"
            else:
                cmd = "show {} prefix-list".format(addr_type)
            show_prefix_list = run_frr_cmd(rnode, cmd)
            for prefix_list in prefix_lists_addr[addr_type].keys():
                if prefix_list in show_prefix_list:
                    errormsg = (
                        "Prefix list {} is/are present in the router"
                        " {}".format(prefix_list, router)
                    )
                    return errormsg

                logger.info(
                    "Prefix list %s is/are not present in the router" " from router %s",
                    prefix_list,
                    router,
                )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=12)
def verify_route_maps(tgen, input_dict):
    """
    Running "show route-map" command and verifying given route-map
    is present in router.
    Parameters
    ----------
    * `tgen` : topogen object
    * `input_dict`: data to verify prefix lists
    Usage
    -----
    # To verify rmap_1 and rmap_2 are present in router r1
    input_dict = {
        "r1": {
            "route_maps": ["rmap_1", "rmap_2"]
        }
    }
    result = verify_route_maps(tgen, input_dict)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router in input_dict.keys():
        if router not in router_list:
            continue

        rnode = router_list[router]
        # Show ip route-map
        show_route_maps = rnode.vtysh_cmd("show route-map")

        # Verify route-map is deleted
        route_maps = input_dict[router]["route_maps"]
        for route_map in route_maps:
            if route_map in show_route_maps:
                errormsg = "Route map {} is not deleted from router" " {}".format(
                    route_map, router
                )
                return errormsg

        logger.info(
            "Route map %s is/are deleted successfully from" " router %s",
            route_maps,
            router,
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=16)
def verify_bgp_community(tgen, addr_type, router, network, input_dict=None):
    """
    API to veiryf BGP large community is attached in route for any given
    DUT by running "show bgp ipv4/6 {route address} json" command.
    Parameters
    ----------
    * `tgen`: topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `network`: network for which set criteria needs to be verified
    * `input_dict`: having details like - for which router, community and
            values needs to be verified
    Usage
    -----
    networks = ["200.50.2.0/32"]
    input_dict = {
        "largeCommunity": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
    }
    result = verify_bgp_community(tgen, "ipv4", dut, network, input_dict=None)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    router_list = tgen.routers()
    if router not in router_list:
        return False

    rnode = router_list[router]

    logger.debug(
        "Verifying BGP community attributes on dut %s: for %s " "network %s",
        router,
        addr_type,
        network,
    )

    for net in network:
        cmd = "show bgp {} {} json".format(addr_type, net)
        show_bgp_json = rnode.vtysh_cmd(cmd, isjson=True)
        logger.info(show_bgp_json)
        if "paths" not in show_bgp_json:
            return "Prefix {} not found in BGP table of router: {}".format(net, router)

        as_paths = show_bgp_json["paths"]
        found = False
        for i in range(len(as_paths)):
            if (
                "largeCommunity" in show_bgp_json["paths"][i]
                or "community" in show_bgp_json["paths"][i]
            ):
                found = True
                logger.info(
                    "Large Community attribute is found for route:" " %s in router: %s",
                    net,
                    router,
                )
                if input_dict is not None:
                    for criteria, comm_val in input_dict.items():
                        show_val = show_bgp_json["paths"][i][criteria]["string"]
                        if comm_val == show_val:
                            logger.info(
                                "Verifying BGP %s for prefix: %s"
                                " in router: %s, found expected"
                                " value: %s",
                                criteria,
                                net,
                                router,
                                comm_val,
                            )
                        else:
                            errormsg = (
                                "Failed: Verifying BGP attribute"
                                " {} for route: {} in router: {}"
                                ", expected  value: {} but found"
                                ": {}".format(criteria, net, router, comm_val, show_val)
                            )
                            return errormsg

        if not found:
            errormsg = (
                "Large Community attribute is not found for route: "
                "{} in router: {} ".format(net, router)
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def get_ipv6_linklocal_address(topo, node, intf):
    """
    API to get the link local ipv6 address of a particular interface

    Parameters
    ----------
    * `node`: node on which link local ip to be fetched.
    * `intf` : interface for which link local ip needs to be returned.
    * `topo` : base topo

    Usage
    -----
    result = get_ipv6_linklocal_address(topo, 'r1', 'r2')

    Returns link local ip of interface between r1 and r2.

    Returns
    -------
    1) link local ipv6 address from the interface
    2) errormsg - when link local ip not found
    """
    tgen = get_topogen()
    ext_nh = tgen.net[node].get_ipv6_linklocal()
    req_nh = topo[node]["links"][intf]["interface"]
    llip = None
    for llips in ext_nh:
        if llips[0] == req_nh:
            llip = llips[1]
            logger.info("Link local ip found = %s", llip)
            return llip

    errormsg = "Failed: Link local ip not found on router {}, " "interface {}".format(
        node, intf
    )

    return errormsg


def verify_create_community_list(tgen, input_dict):
    """
    API is to verify if large community list is created for any given DUT in
    input_dict by running "sh bgp large-community-list {"comm_name"} detail"
    command.
    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict`: having details like - for which router, large community
                    needs to be verified
    Usage
    -----
    input_dict = {
        "r1": {
            "large-community-list": {
                "standard": {
                     "Test1": [{"action": "PERMIT", "attribute":\
                                    ""}]
                }}}}
    result = verify_create_community_list(tgen, input_dict)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router in input_dict.keys():
        if router not in router_list:
            continue

        rnode = router_list[router]

        logger.info("Verifying large-community is created for dut %s:", router)

        for comm_data in input_dict[router]["bgp_community_lists"]:
            comm_name = comm_data["name"]
            comm_type = comm_data["community_type"]
            show_bgp_community = run_frr_cmd(
                rnode, "show bgp large-community-list {} detail".format(comm_name)
            )

            # Verify community list and type
            if comm_name in show_bgp_community and comm_type in show_bgp_community:
                logger.info(
                    "BGP %s large-community-list %s is" " created", comm_type, comm_name
                )
            else:
                errormsg = "BGP {} large-community-list {} is not" " created".format(
                    comm_type, comm_name
                )
                return errormsg

            logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
            return True


def verify_cli_json(tgen, input_dict):
    """
    API to verify if JSON is available for clis
    command.
    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict`: CLIs for which JSON needs to be verified
    Usage
    -----
    input_dict = {
        "edge1":{
            "cli": ["show evpn vni detail", show evpn rmac vni all]
        }
    }

    result = verify_cli_json(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for dut in input_dict.keys():
        rnode = tgen.gears[dut]

        for cli in input_dict[dut]["cli"]:
            logger.info(
                "[DUT: %s]: Verifying JSON is available for " "CLI %s :", dut, cli
            )

            test_cli = "{} json".format(cli)
            ret_json = rnode.vtysh_cmd(test_cli, isjson=True)
            if not bool(ret_json):
                errormsg = "CLI: %s, JSON format is not available" % (cli)
                return errormsg
            elif "unknown" in ret_json or "Unknown" in ret_json:
                errormsg = "CLI: %s, JSON format is not available" % (cli)
                return errormsg
            else:
                logger.info(
                    "CLI : %s JSON format is available: " "\n %s", cli, ret_json
                )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


@retry(retry_timeout=12)
def verify_evpn_vni(tgen, input_dict):
    """
    API to verify evpn vni details using "show evpn vni detail json"
    command.

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict`: having details like - for which router, evpn details
                    needs to be verified
    Usage
    -----
    input_dict = {
        "edge1":{
            "vni": [
                {
                    "75100":{
                        "vrf": "RED",
                        "vxlanIntf": "vxlan75100",
                        "localVtepIp": "120.1.1.1",
                        "sviIntf": "br100"
                    }
                }
            ]
        }
    }

    result = verify_evpn_vni(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for dut in input_dict.keys():
        rnode = tgen.gears[dut]

        logger.info("[DUT: %s]: Verifying evpn vni details :", dut)

        cmd = "show evpn vni detail json"
        evpn_all_vni_json = run_frr_cmd(rnode, cmd, isjson=True)
        if not bool(evpn_all_vni_json):
            errormsg = "No output for '{}' cli".format(cmd)
            return errormsg

        if "vni" in input_dict[dut]:
            for vni_dict in input_dict[dut]["vni"]:
                found = False
                vni = vni_dict["name"]
                for evpn_vni_json in evpn_all_vni_json:
                    if "vni" in evpn_vni_json:
                        if evpn_vni_json["vni"] != int(vni):
                            continue

                        for attribute in vni_dict.keys():
                            if vni_dict[attribute] != evpn_vni_json[attribute]:
                                errormsg = (
                                    "[DUT: %s] Verifying "
                                    "%s for VNI: %s [FAILED]||"
                                    ", EXPECTED  : %s "
                                    " FOUND : %s"
                                    % (
                                        dut,
                                        attribute,
                                        vni,
                                        vni_dict[attribute],
                                        evpn_vni_json[attribute],
                                    )
                                )
                                return errormsg

                            else:
                                found = True
                                logger.info(
                                    "[DUT: %s] Verifying"
                                    " %s for VNI: %s , "
                                    "Found Expected : %s ",
                                    dut,
                                    attribute,
                                    vni,
                                    evpn_vni_json[attribute],
                                )

                        if evpn_vni_json["state"] != "Up":
                            errormsg = (
                                "[DUT: %s] Failed: Verifying"
                                " State for VNI: %s is not Up" % (dut, vni)
                            )
                            return errormsg

                    else:
                        errormsg = (
                            "[DUT: %s] Failed:"
                            " VNI: %s is not present in JSON" % (dut, vni)
                        )
                        return errormsg

                    if found:
                        logger.info(
                            "[DUT %s]: Verifying VNI : %s "
                            "details and state is Up [PASSED]!!",
                            dut,
                            vni,
                        )
                        return True

        else:
            errormsg = (
                "[DUT: %s] Failed:" " vni details are not present in input data" % (dut)
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return False


@retry(retry_timeout=12)
def verify_vrf_vni(tgen, input_dict):
    """
    API to verify vrf vni details using "show vrf vni json"
    command.
    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict`: having details like - for which router, evpn details
                    needs to be verified
    Usage
    -----
    input_dict = {
        "edge1":{
            "vrfs": [
                {
                    "RED":{
                        "vni": 75000,
                        "vxlanIntf": "vxlan75100",
                        "sviIntf": "br100",
                        "routerMac": "00:80:48:ba:d1:00",
                        "state": "Up"
                    }
                }
            ]
        }
    }

    result = verify_vrf_vni(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for dut in input_dict.keys():
        rnode = tgen.gears[dut]

        logger.info("[DUT: %s]: Verifying vrf vni details :", dut)

        cmd = "show vrf vni json"
        vrf_all_vni_json = run_frr_cmd(rnode, cmd, isjson=True)
        if not bool(vrf_all_vni_json):
            errormsg = "No output for '{}' cli".format(cmd)
            return errormsg

        if "vrfs" in input_dict[dut]:
            for vrfs in input_dict[dut]["vrfs"]:
                for vrf, vrf_dict in vrfs.items():
                    found = False
                    for vrf_vni_json in vrf_all_vni_json["vrfs"]:
                        if "vrf" in vrf_vni_json:
                            if vrf_vni_json["vrf"] != vrf:
                                continue

                            for attribute in vrf_dict.keys():
                                if vrf_dict[attribute] == vrf_vni_json[attribute]:
                                    found = True
                                    logger.info(
                                        "[DUT %s]: VRF: %s, "
                                        "verifying %s "
                                        ", Found Expected: %s "
                                        "[PASSED]!!",
                                        dut,
                                        vrf,
                                        attribute,
                                        vrf_vni_json[attribute],
                                    )
                                else:
                                    errormsg = (
                                        "[DUT: %s] VRF: %s, "
                                        "verifying %s [FAILED!!] "
                                        ", EXPECTED : %s "
                                        ", FOUND : %s"
                                        % (
                                            dut,
                                            vrf,
                                            attribute,
                                            vrf_dict[attribute],
                                            vrf_vni_json[attribute],
                                        )
                                    )
                                    return errormsg

                        else:
                            errormsg = "[DUT: %s] VRF: %s " "is not present in JSON" % (
                                dut,
                                vrf,
                            )
                            return errormsg

                        if found:
                            logger.info(
                                "[DUT %s] Verifying VRF: %s " " details [PASSED]!!",
                                dut,
                                vrf,
                            )
                            return True

        else:
            errormsg = (
                "[DUT: %s] Failed:" " vrf details are not present in input data" % (dut)
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return False


def required_linux_kernel_version(required_version):
    """
    This API is used to check linux version compatibility of the test suite.
    If version mentioned in required_version is higher than the linux kernel
    of the system, test suite will be skipped. This API returns true or errormsg.

    Parameters
    ----------
    * `required_version` : Kernel version required for the suites to run.

    Usage
    -----
    result = linux_kernel_version_lowerthan('4.15')

    Returns
    -------
    errormsg(str) or True
    """
    system_kernel = platform.release()
    if version_cmp(system_kernel, required_version) < 0:
        error_msg = (
            'These tests will not run on kernel "{}", '
            "they require kernel >= {})".format(system_kernel, required_version)
        )

        logger.info(error_msg)

        return error_msg
    return True


class HostApplicationHelper(object):
    """Helper to track and cleanup per-host based test processes."""

    def __init__(self, tgen=None, base_cmd=None):
        self.base_cmd_str = ""
        self.host_procs = {}
        self.tgen = None
        self.set_base_cmd(base_cmd if base_cmd else [])
        if tgen is not None:
            self.init(tgen)

    def __enter__(self):
        self.init()
        return self

    def __exit__(self, type, value, traceback):
        self.cleanup()

    def __str__(self):
        return "HostApplicationHelper({})".format(self.base_cmd_str)

    def set_base_cmd(self, base_cmd):
        assert isinstance(base_cmd, list) or isinstance(base_cmd, tuple)
        self.base_cmd = base_cmd
        if base_cmd:
            self.base_cmd_str = " ".join(base_cmd)
        else:
            self.base_cmd_str = ""

    def init(self, tgen=None):
        """Initialize the helper with tgen if needed.

        If overridden, need to handle multiple entries but one init. Will be called on
        object creation if tgen is supplied. Will be called again on __enter__ so should
        not re-init if already inited.
        """
        if self.tgen:
            assert tgen is None or self.tgen == tgen
        else:
            self.tgen = tgen

    def started_proc(self, host, p):
        """Called after process started on host.

        Return value is passed to `stopping_proc` method."""
        logger.debug("%s: Doing nothing after starting process", self)
        return False

    def stopping_proc(self, host, p, info):
        """Called after process started on host."""
        logger.debug("%s: Doing nothing before stopping process", self)

    def _add_host_proc(self, host, p):
        v = self.started_proc(host, p)

        if host not in self.host_procs:
            self.host_procs[host] = []
        logger.debug("%s: %s: tracking process %s", self, host, p)
        self.host_procs[host].append((p, v))

    def stop_host(self, host):
        """Stop the process on the host.

        Override to do additional cleanup."""
        if host in self.host_procs:
            hlogger = self.tgen.net[host].logger
            for p, v in self.host_procs[host]:
                self.stopping_proc(host, p, v)
                logger.debug("%s: %s: terminating process %s", self, host, p.pid)
                hlogger.debug("%s: %s: terminating process %s", self, host, p.pid)
                rc = p.poll()
                if rc is not None:
                    logger.error(
                        "%s: %s: process early exit %s: %s",
                        self,
                        host,
                        p.pid,
                        comm_error(p),
                    )
                    hlogger.error(
                        "%s: %s: process early exit %s: %s",
                        self,
                        host,
                        p.pid,
                        comm_error(p),
                    )
                else:
                    p.terminate()
                    p.wait()
                    logger.debug(
                        "%s: %s: terminated process %s: %s",
                        self,
                        host,
                        p.pid,
                        comm_error(p),
                    )
                    hlogger.debug(
                        "%s: %s: terminated process %s: %s",
                        self,
                        host,
                        p.pid,
                        comm_error(p),
                    )

            del self.host_procs[host]

    def stop_all_hosts(self):
        hosts = set(self.host_procs)
        for host in hosts:
            self.stop_host(host)

    def cleanup(self):
        self.stop_all_hosts()

    def run(self, host, cmd_args, **kwargs):
        cmd = list(self.base_cmd)
        cmd.extend(cmd_args)
        p = self.tgen.gears[host].popen(cmd, **kwargs)
        assert p.poll() is None
        self._add_host_proc(host, p)
        return p

    def check_procs(self):
        """Check that all current processes are running, log errors if not.

        Returns: List of stopped processes."""
        procs = []

        logger.debug("%s: checking procs on hosts %s", self, self.host_procs.keys())

        for host in self.host_procs:
            hlogger = self.tgen.net[host].logger
            for p, _ in self.host_procs[host]:
                logger.debug("%s: checking %s proc %s", self, host, p)
                rc = p.poll()
                if rc is None:
                    continue
                logger.error(
                    "%s: %s proc exited: %s", self, host, comm_error(p), exc_info=True
                )
                hlogger.error(
                    "%s: %s proc exited: %s", self, host, comm_error(p), exc_info=True
                )
                procs.append(p)
        return procs


class IPerfHelper(HostApplicationHelper):
    def __str__(self):
        return "IPerfHelper()"

    def run_join(
        self,
        host,
        join_addr,
        l4Type="UDP",
        join_interval=1,
        join_intf=None,
        join_towards=None,
    ):
        """
        Use iperf to send IGMP join and listen to traffic

        Parameters:
        -----------
        * `host`: iperf host from where IGMP join would be sent
        * `l4Type`: string, one of [ TCP, UDP ]
        * `join_addr`: multicast address (or addresses) to join to
        * `join_interval`: seconds between periodic bandwidth reports
        * `join_intf`: the interface to bind the join to
        * `join_towards`: router whos interface to bind the join to

        returns: Success (bool)
        """

        iperf_path = self.tgen.net.get_exec_path("iperf")

        assert join_addr
        if not isinstance(join_addr, list) and not isinstance(join_addr, tuple):
            join_addr = [ipaddress.IPv4Address(frr_unicode(join_addr))]

        for bindTo in join_addr:
            iperf_args = [iperf_path, "-s"]

            if l4Type == "UDP":
                iperf_args.append("-u")

            iperf_args.append("-B")
            if join_towards:
                to_intf = frr_unicode(
                    self.tgen.json_topo["routers"][host]["links"][join_towards][
                        "interface"
                    ]
                )
                iperf_args.append("{}%{}".format(str(bindTo), to_intf))
            elif join_intf:
                iperf_args.append("{}%{}".format(str(bindTo), join_intf))
            else:
                iperf_args.append(str(bindTo))

            if join_interval:
                iperf_args.append("-i")
                iperf_args.append(str(join_interval))

            p = self.run(host, iperf_args)
            if p.poll() is not None:
                logger.error("IGMP join failed on %s: %s", bindTo, comm_error(p))
                return False
        return True

    def run_traffic(
        self, host, sentToAddress, ttl, time=0, l4Type="UDP", bind_towards=None
    ):
        """
        Run iperf to send IGMP join and traffic

        Parameters:
        -----------
        * `host`: iperf host to send traffic from
        * `l4Type`: string, one of [ TCP, UDP ]
        * `sentToAddress`: multicast address to send traffic to
        * `ttl`: time to live
        * `time`: time in seconds to transmit for
        * `bind_towards`: Router who's interface the source ip address is got from

        returns: Success (bool)
        """

        iperf_path = self.tgen.net.get_exec_path("iperf")

        if sentToAddress and not isinstance(sentToAddress, list):
            sentToAddress = [ipaddress.IPv4Address(frr_unicode(sentToAddress))]

        for sendTo in sentToAddress:
            iperf_args = [iperf_path, "-c", sendTo]

            # Bind to Interface IP
            if bind_towards:
                ifaddr = frr_unicode(
                    self.tgen.json_topo["routers"][host]["links"][bind_towards]["ipv4"]
                )
                ipaddr = ipaddress.IPv4Interface(ifaddr).ip
                iperf_args.append("-B")
                iperf_args.append(str(ipaddr))

            # UDP/TCP
            if l4Type == "UDP":
                iperf_args.append("-u")
                iperf_args.append("-b")
                iperf_args.append("0.012m")

            # TTL
            if ttl:
                iperf_args.append("-T")
                iperf_args.append(str(ttl))

            # Time
            if time:
                iperf_args.append("-t")
                iperf_args.append(str(time))

            p = self.run(host, iperf_args)
            if p.poll() is not None:
                logger.error(
                    "mcast traffic send failed for %s: %s", sendTo, comm_error(p)
                )
                return False

        return True


def verify_ip_nht(tgen, input_dict):
    """
    Running "show ip nht" command and verifying given nexthop resolution
    Parameters
    ----------
    * `tgen` : topogen object
    * `input_dict`: data to verify nexthop
    Usage
    -----
    input_dict_4 = {
            "r1": {
                nh: {
                    "Address": nh,
                    "resolvedVia": "connected",
                    "nexthops": {
                        "nexthop1": {
                            "Interface": intf
                        }
                    }
                }
            }
        }
    result = verify_ip_nht(tgen, input_dict_4)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: verify_ip_nht()")

    router_list = tgen.routers()
    for router in input_dict.keys():
        if router not in router_list:
            continue

        rnode = router_list[router]
        nh_list = input_dict[router]

        if validate_ip_address(next(iter(nh_list))) == "ipv6":
            show_ip_nht = run_frr_cmd(rnode, "show ipv6 nht")
        else:
            show_ip_nht = run_frr_cmd(rnode, "show ip nht")

        for nh in nh_list:
            if nh in show_ip_nht:
                nht = run_frr_cmd(rnode, "show ip nht {}".format(nh))
                if "unresolved" in nht:
                    errormsg = "Nexthop {} became unresolved on {}".format(nh, router)
                    return errormsg
                else:
                    logger.info("Nexthop %s is resolved on %s", nh, router)
                    return True
            else:
                errormsg = "Nexthop {} is resolved on {}".format(nh, router)
                return errormsg

    logger.debug("Exiting lib API: verify_ip_nht()")
    return False


def scapy_send_raw_packet(tgen, topo, senderRouter, intf, packet=None):
    """
    Using scapy Raw() method to send BSR raw packet from one FRR
    to other

    Parameters:
    -----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `senderRouter` : Sender router
    * `packet` : packet in raw format

    returns:
    --------
    errormsg or True
    """

    global CD
    result = ""
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    sender_interface = intf
    rnode = tgen.routers()[senderRouter]

    for destLink, data in topo["routers"][senderRouter]["links"].items():
        if "type" in data and data["type"] == "loopback":
            continue

        if not packet:
            packet = topo["routers"][senderRouter]["pkt"]["test_packets"][packet][
                "data"
            ]

        python3_path = tgen.net.get_exec_path(["python3", "python"])
        script_path = os.path.join(CD, "send_bsr_packet.py")
        cmd = "{} {} '{}' '{}' --interval=1 --count=1".format(
            python3_path, script_path, packet, sender_interface
        )

        logger.info("Scapy cmd: \n %s", cmd)
        result = rnode.run(cmd)

        if result == "":
            return result

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True
