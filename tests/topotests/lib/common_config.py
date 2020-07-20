#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

from collections import OrderedDict
from datetime import datetime
from time import sleep
from copy import deepcopy
from subprocess import call
from subprocess import STDOUT as SUB_STDOUT
from subprocess import PIPE as SUB_PIPE
from subprocess import Popen
from functools import wraps
from re import search as re_search
from tempfile import mkdtemp

import StringIO
import os
import sys
import ConfigParser
import traceback
import socket
import ipaddress

from lib.topolog import logger, logger_config
from lib.topogen import TopoRouter, get_topogen
from lib.topotest import interface_set_status

FRRCFG_FILE = "frr_json.conf"
FRRCFG_BKUP_FILE = "frr_json_initial.conf"

ERROR_LIST = ["Malformed", "Failure", "Unknown", "Incomplete"]
ROUTER_LIST = []

####
CD = os.path.dirname(os.path.realpath(__file__))
PYTESTINI_PATH = os.path.join(CD, "../pytest.ini")

# Creating tmp dir with testsuite name to avoid conflict condition when
# multiple testsuites run together. All temporary files would be created
# in this dir and this dir would be removed once testsuite run is
# completed
LOGDIR = "/tmp/topotests/"
TMPDIR = None

# NOTE: to save execution logs to log file frrtest_log_dir must be configured
# in `pytest.ini`.
config = ConfigParser.ConfigParser()
config.read(PYTESTINI_PATH)

config_section = "topogen"

if config.has_option("topogen", "verbosity"):
    loglevel = config.get("topogen", "verbosity")
    loglevel = loglevel.upper()
else:
    loglevel = "INFO"

if config.has_option("topogen", "frrtest_log_dir"):
    frrtest_log_dir = config.get("topogen", "frrtest_log_dir")
    time_stamp = datetime.time(datetime.now())
    logfile_name = "frr_test_bgp_"
    frrtest_log_file = frrtest_log_dir + logfile_name + str(time_stamp)
    print("frrtest_log_file..", frrtest_log_file)

    logger = logger_config.get_logger(
        name="test_execution_logs", log_level=loglevel, target=frrtest_log_file
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

    pass


def run_frr_cmd(rnode, cmd, isjson=False):
    """
    Execute frr show commands in priviledged mode
    * `rnode`: router node on which commands needs to executed
    * `cmd`: Command to be executed on frr
    * `isjson`: If command is to get json data or not
    :return str:
    """

    if cmd:
        ret_data = rnode.vtysh_cmd(cmd, isjson=isjson)

        if True:
            if isjson:
                logger.debug(ret_data)
                print_data = rnode.vtysh_cmd(cmd.rstrip("json"), isjson=False)
            else:
                print_data = ret_data

            logger.info(
                "Output for command [ %s] on router %s:\n%s",
                cmd.rstrip("json"),
                rnode.name,
                print_data,
            )
        return ret_data

    else:
        raise InvalidCLIError("No actual cmd passed")


def apply_raw_config(tgen, input_dict):

    """
    API to configure raw configuration on device. This can be used for any cli
    which does has not been implemented in JSON.

    Parameters
    ----------
    * `tgen`: tgen onject
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

    result = True
    for router_name in input_dict.keys():
        config_cmd = input_dict[router_name]["raw_config"]

        if not isinstance(config_cmd, list):
            config_cmd = [config_cmd]

        frr_cfg_file = "{}/{}/{}".format(TMPDIR, router_name, FRRCFG_FILE)
        with open(frr_cfg_file, "w") as cfg:
            for cmd in config_cmd:
                cfg.write("{}\n".format(cmd))

        result = load_config_to_router(tgen, router_name)

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
    * `tgen`: tgen onject
    * `data`: Congiguration data saved in a list.
    * `router` : router id to be configured.
    * `config_type` : Syntactic information while writing configuration. Should
                      be one of the value as mentioned in the config_map below.
    * `build` : Only for initial setup phase this is set as True
    Returns
    -------
    True or False
    """
    TMPDIR = os.path.join(LOGDIR, tgen.modname)

    fname = "{}/{}/{}".format(TMPDIR, router, FRRCFG_FILE)

    config_map = OrderedDict(
        {
            "general_config": "! FRR General Config\n",
            "interface_config": "! Interfaces Config\n",
            "static_route": "! Static Route Config\n",
            "prefix_list": "! Prefix List Config\n",
            "bgp_community_list": "! Community List Config\n",
            "route_maps": "! Route Maps Config\n",
            "bgp": "! BGP Config\n",
            "vrf": "! VRF Config\n",
        }
    )

    if build:
        mode = "a"
    elif not load_config:
        mode = "a"
    else:
        mode = "w"

    try:
        frr_cfg_fd = open(fname, mode)
        if config_type:
            frr_cfg_fd.write(config_map[config_type])
        for line in data:
            frr_cfg_fd.write("{} \n".format(str(line)))
        frr_cfg_fd.write("\n")

    except IOError as err:
        logger.error(
            "Unable to open FRR Config File. error(%s): %s" % (err.errno, err.strerror)
        )
        return False
    finally:
        frr_cfg_fd.close()

    # If configuration applied from build, it will done at last
    if not build and load_config:
        load_config_to_router(tgen, router)

    return True


def kill_router_daemons(tgen, router, daemons):
    """
    Router's current config would be saved to /etc/frr/ for each deamon
    and deamon would be killed forcefully using SIGKILL.
    * `tgen`  : topogen object
    * `router`: Device under test
    * `daemons`: list of daemons to be killed
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        router_list = tgen.routers()

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
        result = router_list[router].startDaemons(daemons)
        return result

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def kill_mininet_routers_process(tgen):
    """
    Kill all mininet stale router' processes
    * `tgen`  : topogen object
    """

    router_list = tgen.routers()
    for rname, router in router_list.iteritems():
        daemon_list = [
            "zebra",
            "ospfd",
            "ospf6d",
            "bgpd",
            "ripd",
            "ripngd",
            "isisd",
            "pimd",
            "ldpd",
            "staticd",
        ]
        for daemon in daemon_list:
            router.run("killall -9 {}".format(daemon))


def check_router_status(tgen):
    """
    Check if all daemons are running for all routers in topology
    * `tgen`  : topogen object
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        router_list = tgen.routers()
        for router, rnode in router_list.iteritems():

            result = rnode.check_router_running()
            if result != "":
                daemons = []
                if "bgpd" in result:
                    daemons.append("bgpd")
                if "zebra" in result:
                    daemons.append("zebra")

                rnode.startDaemons(daemons)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


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

    router_list = tgen.routers()
    for rname in ROUTER_LIST:
        if routerName and routerName != rname:
            continue

        router = router_list[rname]
        logger.info("Configuring router %s to initial test configuration", rname)

        cfg = router.run("vtysh -c 'show running'")
        fname = "{}/{}/frr.sav".format(TMPDIR, rname)
        dname = "{}/{}/delta.conf".format(TMPDIR, rname)
        f = open(fname, "w")
        for line in cfg.split("\n"):
            line = line.strip()

            if (
                line == "Building configuration..."
                or line == "Current configuration:"
                or not line
            ):
                continue
            f.write(line)
            f.write("\n")

        f.close()
        run_cfg_file = "{}/{}/frr.sav".format(TMPDIR, rname)
        init_cfg_file = "{}/{}/frr_json_initial.conf".format(TMPDIR, rname)
        command = "/usr/lib/frr/frr-reload.py  --input {} --test {} > {}".format(
            run_cfg_file, init_cfg_file, dname
        )
        result = call(command, shell=True, stderr=SUB_STDOUT, stdout=SUB_PIPE)

        # Assert if command fail
        if result > 0:
            logger.error("Delta file creation failed. Command executed %s", command)
            with open(run_cfg_file, "r") as fd:
                logger.info(
                    "Running configuration saved in %s is:\n%s", run_cfg_file, fd.read()
                )
            with open(init_cfg_file, "r") as fd:
                logger.info(
                    "Test configuration saved in %s is:\n%s", init_cfg_file, fd.read()
                )

            err_cmd = ["/usr/bin/vtysh", "-m", "-f", run_cfg_file]
            result = Popen(err_cmd, stdout=SUB_PIPE, stderr=SUB_PIPE)
            output = result.communicate()
            for out_data in output:
                temp_data = out_data.decode("utf-8").lower()
                for out_err in ERROR_LIST:
                    if out_err.lower() in temp_data:
                        logger.error(
                            "Found errors while validating data in" " %s", run_cfg_file
                        )
                        raise InvalidCLIError(out_data)
            raise InvalidCLIError("Unknown error in %s", output)

        f = open(dname, "r")
        delta = StringIO.StringIO()
        delta.write("configure terminal\n")
        t_delta = f.read()

        # Don't disable debugs
        check_debug = True

        for line in t_delta.split("\n"):
            line = line.strip()
            if line == "Lines To Delete" or line == "===============" or not line:
                continue

            if line == "Lines To Add":
                check_debug = False
                continue

            if line == "============" or not line:
                continue

            # Leave debugs and log output alone
            if check_debug:
                if "debug" in line or "log file" in line:
                    continue

            delta.write(line)
            delta.write("\n")

        f.close()

        delta.write("end\n")

        output = router.vtysh_multicmd(delta.getvalue(), pretty_output=False)

        delta.close()
        delta = StringIO.StringIO()
        cfg = router.run("vtysh -c 'show running'")
        for line in cfg.split("\n"):
            line = line.strip()
            delta.write(line)
            delta.write("\n")

        # Router current configuration to log file or console if
        # "show_router_config" is defined in "pytest.ini"
        if show_router_config:
            logger.info("Configuration on router {} after reset:".format(rname))
            logger.info(delta.getvalue())
        delta.close()

    logger.debug("Exiting API: reset_config_on_routers")
    return True


def load_config_to_router(tgen, routerName, save_bkup=False):
    """
    Loads configuration on router from the file FRRCFG_FILE.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `routerName` : router for which configuration to be loaded
    * `save_bkup` : If True, Saves snapshot of FRRCFG_FILE to FRRCFG_BKUP_FILE
    """

    logger.debug("Entering API: load_config_to_router")

    router_list = tgen.routers()
    for rname in ROUTER_LIST:
        if routerName and rname != routerName:
            continue

        router = router_list[rname]
        try:
            frr_cfg_file = "{}/{}/{}".format(TMPDIR, rname, FRRCFG_FILE)
            frr_cfg_bkup = "{}/{}/{}".format(TMPDIR, rname, FRRCFG_BKUP_FILE)
            with open(frr_cfg_file, "r+") as cfg:
                data = cfg.read()
                logger.info(
                    "Applying following configuration on router"
                    " {}:\n{}".format(rname, data)
                )
                if save_bkup:
                    with open(frr_cfg_bkup, "w") as bkup:
                        bkup.write(data)

                output = router.vtysh_multicmd(data, pretty_output=False)
                for out_err in ERROR_LIST:
                    if out_err.lower() in output.lower():
                        raise InvalidCLIError("%s" % output)

                cfg.truncate(0)

        except IOError as err:
            errormsg = (
                "Unable to open config File. error(%s):" "  %s",
                (err.errno, err.strerror),
            )
            return errormsg

        # Router current configuration to log file or console if
        # "show_router_config" is defined in "pytest.ini"
        if show_router_config:
            logger.info("New configuration for router {}:".format(rname))
            new_config = router.run("vtysh -c 'show running'")
            logger.info(new_config)

    logger.debug("Exiting API: load_config_to_router")
    return True


def get_frr_ipv6_linklocal(tgen, router, intf=None, vrf=None):
    """
    API to get the link local ipv6 address of a perticular interface using
    FRR command 'show interface'

    * `tgen`: tgen onject
    * `router` : router for which hightest interface should be
                 calculated
    * `intf` : interface for which linklocal address needs to be taken
    * `vrf` : VRF name

    Usage
    -----
    linklocal = get_frr_ipv6_linklocal(tgen, router, "intf1", RED_A)

    Returns
    -------
    1) array of interface names to link local ips.
    """

    router_list = tgen.routers()
    for rname, rnode in router_list.iteritems():
        if rname != router:
            continue

        linklocal = []

        if vrf:
            cmd = "show interface vrf {}".format(vrf)
        else:
            cmd = "show interface"

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
            m1 = re_search("inet6 (fe80[:a-fA-F0-9]+[\/0-9]+)", line)
            if m1:
                local = m1.group(1)
                ll_per_if_count += 1
                if ll_per_if_count > 1:
                    linklocal += [["%s-%s" % (interface, ll_per_if_count), local]]
                else:
                    linklocal += [[interface, local]]

    if linklocal:
        if intf:
            return [_linklocal[1] for _linklocal in linklocal if _linklocal[0] == intf][
                0
            ].split("/")[0]
        return linklocal
    else:
        errormsg = "Link local ip missing on router {}"
        return errormsg


def generate_support_bundle():
    """
    API to generate support bundle on any verification ste failure.
    it runs a python utility, /usr/lib/frr/generate_support_bundle.py,
    which basically runs defined CLIs and dumps the data to specified location
    """

    tgen = get_topogen()
    router_list = tgen.routers()
    test_name = sys._getframe(2).f_code.co_name
    TMPDIR = os.path.join(LOGDIR, tgen.modname)

    for rname, rnode in router_list.iteritems():
        logger.info("Generating support bundle for {}".format(rname))
        rnode.run("mkdir -p /var/log/frr")
        bundle_log = rnode.run("python2 /usr/lib/frr/generate_support_bundle.py")
        logger.info(bundle_log)

        dst_bundle = "{}/{}/support_bundles/{}".format(TMPDIR, rname, test_name)
        src_bundle = "/var/log/frr"
        rnode.run("rm -rf {}".format(dst_bundle))
        rnode.run("mkdir -p {}".format(dst_bundle))
        rnode.run("mv -f {}/* {}".format(src_bundle, dst_bundle))

    return True


def start_topology(tgen):
    """
    Starting topology, create tmp files which are loaded to routers
    to start deamons and then start routers
    * `tgen`  : topogen object
    """

    global TMPDIR, ROUTER_LIST
    # Starting topology
    tgen.start_topology()

    # Starting deamons

    router_list = tgen.routers()
    ROUTER_LIST = sorted(
        router_list.keys(), key=lambda x: int(re_search("\d+", x).group(0))
    )
    TMPDIR = os.path.join(LOGDIR, tgen.modname)

    router_list = tgen.routers()
    for rname in ROUTER_LIST:
        router = router_list[rname]

        # It will help in debugging the failures, will give more details on which
        # specific kernel version tests are failing
        linux_ver = router.run("uname -a")
        logger.info("Logging platform related details: \n %s \n", linux_ver)

        try:
            os.chdir(TMPDIR)

            # Creating router named dir and empty zebra.conf bgpd.conf files
            # inside the current directory
            if os.path.isdir("{}".format(rname)):
                os.system("rm -rf {}".format(rname))
                os.mkdir("{}".format(rname))
                os.system("chmod -R go+rw {}".format(rname))
                os.chdir("{}/{}".format(TMPDIR, rname))
                os.system("touch zebra.conf bgpd.conf")
            else:
                os.mkdir("{}".format(rname))
                os.system("chmod -R go+rw {}".format(rname))
                os.chdir("{}/{}".format(TMPDIR, rname))
                os.system("touch zebra.conf bgpd.conf")

        except IOError as (errno, strerror):
            logger.error("I/O error({0}): {1}".format(errno, strerror))

        # Loading empty zebra.conf file to router, to start the zebra deamon
        router.load_config(
            TopoRouter.RD_ZEBRA, "{}/{}/zebra.conf".format(TMPDIR, rname)
        )
        # Loading empty bgpd.conf file to router, to start the bgp deamon
        router.load_config(TopoRouter.RD_BGP, "{}/{}/bgpd.conf".format(TMPDIR, rname))

        # Starting routers
    logger.info("Starting all routers once topology is created")
    tgen.start_router()


def stop_router(tgen, router):
    """
    Router"s current config would be saved to /etc/frr/ for each deamon
    and router and its deamons would be stopped.

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
    Router will started and config would be loaded from /etc/frr/ for each
    deamon

    * `tgen`  : topogen object
    * `router`: Device under test
    """

    logger.debug("Entering lib API: start_router")

    try:
        router_list = tgen.routers()

        # Router and its deamons would be started and config would
        #  be loaded to router for each deamon from /etc/frr
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
        for c_router, c_data in input_dict.iteritems():
            rnode = tgen.routers()[c_router]
            if "vrfs" in c_data:
                for vrf in c_data["vrfs"]:
                    config_data = []
                    del_action = vrf.setdefault("delete", False)
                    name = vrf.setdefault("name", None)
                    table_id = vrf.setdefault("id", None)
                    vni = vrf.setdefault("vni", None)
                    del_vni = vrf.setdefault("no_vni", None)

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

                            if "links" in c_data:
                                for destRouterLink, data in sorted(
                                    c_data["links"].iteritems()
                                ):
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

                        result = create_common_configuration(
                            tgen, c_router, config_data, "vrf", build=build
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

    rnode = tgen.routers()[dut]

    if create:
        cmd = "sudo ip link add name {} type dummy".format(name)
        rnode.run(cmd)

    addr_type = validate_ip_address(ip_addr)
    if addr_type == "ipv4":
        cmd = "ifconfig {} {} netmask {}".format(name, ip_addr, netmask)
    else:
        cmd = "ifconfig {} inet6 add {}/{}".format(name, ip_addr, netmask)

    rnode.run(cmd)

    if vrf:
        cmd = "ip link set {} master {}".format(name, vrf)
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
        logger.error(
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

        addr_type = validate_ip_address(start_ip)
        if addr_type == "ipv4":
            start_ip = ipaddress.IPv4Address(unicode(start_ip))
            step = 2 ** (32 - mask)
        if addr_type == "ipv6":
            start_ip = ipaddress.IPv6Address(unicode(start_ip))
            step = 2 ** (128 - mask)

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
    * `router` : router for which hightest interface should be calculated
    """

    link_data = topo["routers"][router]["links"]
    lo_list = []
    interfaces_list = []
    lo_exists = False
    for destRouterLink, data in sorted(link_data.iteritems()):
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
    """ Display message at beginning of test case"""
    count = 20
    logger.info("*" * (len(tc_name) + count))
    step("START -> Testcase : %s" % tc_name, reset=True)
    logger.info("*" * (len(tc_name) + count))


def write_test_footer(tc_name):
    """ Display message at end of test case"""
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
        global frr_cfg
        for router in input_dict.keys():

            interface_list = input_dict[router]["interface_list"]
            status = input_dict[router].setdefault("status", "up")
            for intf in interface_list:
                rnode = tgen.routers()[router]
                interface_set_status(rnode, intf, status)

            # Load config to router
            load_config_to_router(tgen, router)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def retry(attempts=3, wait=2, return_is_str=True, initial_wait=0, return_is_dict=False):
    """
    Retries function execution, if return is an errormsg or exception

    * `attempts`: Number of attempts to make
    * `wait`: Number of seconds to wait between each attempt
    * `return_is_str`: Return val is an errormsg in case of failure
    * `initial_wait`: Sleeps for this much seconds before executing function

    """

    def _retry(func):
        @wraps(func)
        def func_retry(*args, **kwargs):
            _wait = kwargs.pop("wait", wait)
            _attempts = kwargs.pop("attempts", attempts)
            _attempts = int(_attempts)
            if _attempts < 0:
                raise ValueError("attempts must be 0 or greater")

            if initial_wait > 0:
                logger.info("Waiting for [%s]s as initial delay", initial_wait)
                sleep(initial_wait)

            _return_is_str = kwargs.pop("return_is_str", return_is_str)
            _return_is_dict = kwargs.pop("return_is_str", return_is_dict)
            for i in range(1, _attempts + 1):
                try:
                    _expected = kwargs.setdefault("expected", True)
                    kwargs.pop("expected")
                    ret = func(*args, **kwargs)
                    logger.debug("Function returned %s" % ret)
                    if _return_is_str and isinstance(ret, bool) and _expected:
                        return ret
                    if (
                        isinstance(ret, str) or isinstance(ret, unicode)
                    ) and _expected is False:
                        return ret
                    if _return_is_dict and isinstance(ret, dict):
                        return ret

                    if _attempts == i:
                        generate_support_bundle()
                        return ret
                except Exception as err:
                    if _attempts == i:
                        generate_support_bundle()
                        logger.info("Max number of attempts (%r) reached", _attempts)
                        raise
                    else:
                        logger.info("Function returned %s", err)
                if i < _attempts:
                    logger.info("Retry [#%r] after sleeping for %ss" % (i, _wait))
                    sleep(_wait)

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
    result = False
    topo = deepcopy(topo)

    try:
        for c_router, c_data in topo.iteritems():
            interface_data = []
            for destRouterLink, data in sorted(c_data["links"].iteritems()):
                # Loopback interfaces
                if "type" in data and data["type"] == "loopback":
                    interface_name = destRouterLink
                else:
                    interface_name = data["interface"]

                # Include vrf if present
                if "vrf" in data:
                    interface_data.append(
                        "interface {} vrf {}".format(
                            str(interface_name), str(data["vrf"])
                        )
                    )
                else:
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

                if "ipv6-link-local" in data:
                    intf_addr = c_data["links"][destRouterLink]["ipv6-link-local"]

                    if "delete" in data and data["delete"]:
                        interface_data.append("no ipv6 address {}".format(intf_addr))
                    else:
                        interface_data.append("ipv6 address {}\n".format(intf_addr))

            result = create_common_configuration(
                tgen, c_router, interface_data, "interface_config", build=build
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

            result = create_common_configuration(
                tgen, router, static_routes_list, "static_route", build=build
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
        for router in input_dict.keys():
            if "prefix_lists" not in input_dict[router]:
                errormsg = "prefix_lists not present in input_dict"
                logger.debug(errormsg)
                continue

            config_data = []
            prefix_lists = input_dict[router]["prefix_lists"]
            for addr_type, prefix_data in prefix_lists.iteritems():
                if not check_address_types(addr_type):
                    continue

                for prefix_name, prefix_list in prefix_data.iteritems():
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
            result = create_common_configuration(
                tgen, router, config_data, "prefix_list", build=build
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
        for router in input_dict.keys():
            if "route_maps" not in input_dict[router]:
                logger.debug("route_maps not present in input_dict")
                continue
            rmap_data = []
            for rmap_name, rmap_value in input_dict[router]["route_maps"].iteritems():

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
                        as_path = set_data.setdefault("path", {})
                        weight = set_data.setdefault("weight", None)
                        community = set_data.setdefault("community", {})
                        large_community = set_data.setdefault("large_community", {})
                        large_comm_list = set_data.setdefault("large_comm_list", {})
                        set_action = set_data.setdefault("set_action", None)
                        nexthop = set_data.setdefault("nexthop", None)
                        origin = set_data.setdefault("origin", None)

                        # Local Preference
                        if local_preference:
                            rmap_data.append(
                                "set local-preference {}".format(local_preference)
                            )

                        # Metric
                        if metric:
                            rmap_data.append("set metric {} \n".format(metric))

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

            result = create_common_configuration(
                tgen, router, rmap_data, "route_maps", build=build
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

                try:
                    community_type = int(community_type)
                    cmd = "{} {} {} {}".format(cmd, community_type, action, value)
                except ValueError:

                    cmd = "{} {} {} {} {}".format(
                        cmd, community_type, name, action, value
                    )

                if del_action:
                    cmd = "no {}".format(cmd)

                config_data.append(cmd)

            result = create_common_configuration(
                tgen, router, config_data, "bgp_community_list", build=build
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
    # Shut down ineterface
    shutdown_bringup_interface(tgen, dut, intf, False)
    # Bring up ineterface
    shutdown_bringup_interface(tgen, dut, intf, True)
    Returns
    -------
    errormsg(str) or True
    """

    router_list = tgen.routers()
    if ifaceaction:
        logger.info("Bringing up interface : {}".format(intf_name))
    else:
        logger.info("Shutting down interface : {}".format(intf_name))

    interface_set_status(router_list[dut], intf_name, ifaceaction)


def addKernelRoute(
    tgen, router, intf, group_addr_range, next_hop=None, src=None, del_action=None
):
    """
    Add route to kernel

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `router`: router for which kernal routes needs to be added
    * `intf`: interface name, for which kernal routes needs to be added
    * `bindToAddress`: bind to <host>, an interface or multicast
                       address

    returns:
    --------
    errormsg or True
    """

    logger.debug("Entering lib API: addKernelRoute()")

    rnode = tgen.routers()[router]

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

        # Verifying if ip route added to kernal
        result = rnode.run(verify_cmd)
        logger.debug("{}\n{}".format(verify_cmd, result))
        if "/" in grp_addr:
            ip, mask = grp_addr.split("/")
            if mask == "32" or mask == "128":
                grp_addr = ip

        if not re_search(r"{}".format(grp_addr), result) and mask is not "0":
            errormsg = (
                "[DUT: {}]: Kernal route is not added for group"
                " address {} Config output: {}".format(router, grp_addr, output)
            )

            return errormsg

    logger.debug("Exiting lib API: addKernelRoute()")
    return True


#############################################
# Verification APIs
#############################################
@retry(attempts=5, wait=2, return_is_str=True, initial_wait=2)
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

    logger.info("Entering lib API: verify_rib()")

    router_list = tgen.routers()
    additional_nexthops_in_required_nhs = []
    found_hops = []
    for routerInput in input_dict.keys():
        for router, rnode in router_list.iteritems():
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
                        st_rt = str(ipaddress.ip_network(unicode(st_rt)))

                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != addr_type:
                            continue

                        if st_rt in rib_routes_json:
                            st_found = True
                            found_routes.append(st_rt)

                            if fib and next_hop:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]

                                for mnh in range(0, len(rib_routes_json[st_rt])):
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
                                ]

                                if found_hops:
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
                                        " route {} in RIB \n".format(dut, _tag, st_rt,)
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
                                        "route {} in RIB \n".format(dut, metric, st_rt,)
                                    )
                                    return errormsg

                        else:
                            missing_routes.append(st_rt)

                if nh_found:
                    logger.info(
                        "[DUT: {}]: Found next_hop {} for all bgp"
                        " routes in RIB".format(router, next_hop)
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
                    st_rt = str(ipaddress.ip_network(unicode(st_rt)))

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

    logger.info("Exiting lib API: verify_rib()")
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

    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

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

    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

        # Show ip prefix list
        show_prefix_list = run_frr_cmd(rnode, "show ip prefix-list")

        # Verify Prefix list is deleted
        prefix_lists_addr = input_dict[router]["prefix_lists"]
        for addr_type in prefix_lists_addr:
            if not check_address_types(addr_type):
                continue

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


@retry(attempts=2, wait=4, return_is_str=True, initial_wait=2)
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

    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]
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


@retry(attempts=3, wait=4, return_is_str=True)
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
    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]

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

    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

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
