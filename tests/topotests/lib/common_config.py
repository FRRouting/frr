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
import os
import ConfigParser
import traceback

from lib.topolog import logger, logger_config
from lib.topogen import TopoRouter


FRRCFG_FILE = "frr_json.conf"
FRRCFG_BKUP_FILE = "frr_json_initial.conf"

ERROR_LIST = ["Malformed", "Failure", "Unknown"]

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

    logger = logger_config.get_logger(name="test_execution_logs",
                                      log_level=loglevel,
                                      target=frrtest_log_file)
    print("Logs will be sent to logfile: {}".format(frrtest_log_file))

if config.has_option("topogen", "show_router_config"):
    show_router_config = config.get("topogen", "show_router_config")
else:
    show_router_config = False


class InvalidCLIError(Exception):
    """Raise when the CLI command is wrong"""
    pass


def create_common_configuration(tgen, router, data, config_type=None,
                                build=False):
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

    config_map = OrderedDict({
        "general_config": "! FRR General Config\n",
        "interface_config": "! Interfaces Config\n"
    })

    if build:
        mode = "a"
    else:
        mode = "w"

    try:
        frr_cfg_fd = open(fname, mode)
        if config_type:
            frr_cfg_fd.write(config_map[config_type])
        for line in data:
            frr_cfg_fd.write("{} \n".format(str(line)))

    except IOError as err:
        logger.error("Unable to open FRR Config File. error(%s): %s" %
                     (err.errno, err.strerror))
        return False
    finally:
        frr_cfg_fd.close()

    # If configuration applied from build, it will done at last
    if not build:
        load_config_to_router(tgen, router)

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
    for rname, router in router_list.iteritems():
        if rname == routerName:
            try:
                frr_cfg_file = "{}/{}/{}".format(TMPDIR, rname, FRRCFG_FILE)
                frr_cfg_bkup = "{}/{}/{}".format(TMPDIR, rname,
                                                 FRRCFG_BKUP_FILE)
                with open(frr_cfg_file, "r") as cfg:
                    data = cfg.read()
                    if save_bkup:
                        with open(frr_cfg_bkup, "w") as bkup:
                            bkup.write(data)

                    output = router.vtysh_multicmd(data, pretty_output=False)
                    for out_err in ERROR_LIST:
                        if out_err.lower() in output.lower():
                            raise InvalidCLIError("%s" % output)
            except IOError as err:
                errormsg = ("Unable to open config File. error(%s):"
                            "  %s", (err.errno, err.strerror))
                return errormsg

            logger.info("New configuration for router {}:".format(rname))
            new_config = router.run("vtysh -c 'show running'")

            # Router current configuration to log file or console if
            # "show_router_config" is defined in "pytest.ini"
            if show_router_config:
                logger.info(new_config)

    logger.debug("Exting API: load_config_to_router")
    return True


def start_topology(tgen):
    """
    Starting topology, create tmp files which are loaded to routers
    to start deamons and then start routers
    * `tgen`  : topogen object
    """

    global TMPDIR
    # Starting topology
    tgen.start_topology()

    # Starting deamons
    router_list = tgen.routers()
    TMPDIR = os.path.join(LOGDIR, tgen.modname)

    # Deleting temporary created dir if exists
    if os.path.exists("{}".format(TMPDIR)):
        os.system("rm -rf {}".format(TMPDIR))

    # Create testsuite named temporary dir to save
    # tmp files
    os.mkdir("{}".format(TMPDIR))

    for rname, router in router_list.iteritems():
        try:
            os.chdir(TMPDIR)

            # Creating rouer named dir and empty zebra.conf bgpd.conf files
            # inside the current directory
            os.mkdir("{}".format(rname))
            os.system("chmod -R go+rw {}".format(rname))
            os.chdir("{}/{}".format(TMPDIR, rname))
            os.system("touch zebra.conf bgpd.conf")

        except IOError as (errno, strerror):
            logger.error("I/O error({0}): {1}".format(errno, strerror))

        # Loading empty zebra.conf file to router, to start the zebra deamon
        router.load_config(
            TopoRouter.RD_ZEBRA,
            "{}/{}/zebra.conf".format(TMPDIR, rname)
            # os.path.join(TMPDIR, "{}/zebra.conf".format(rname))
        )
        # Loading empty bgpd.conf file to router, to start the bgp deamon
        router.load_config(
            TopoRouter.RD_BGP,
            "{}/{}/bgpd.conf".format(TMPDIR, rname)
            # os.path.join(TMPDIR, "{}/bgpd.conf".format(rname))
        )

    # Starting routers
    logger.info("Starting all routers once topology is created")
    tgen.start_router()


def stop_topology(tgen):
    """
    It will stop topology and remove temporary dirs and files.
    * `tgen`  : topogen object
    """

    # This function tears down the whole topology.
    tgen.stop_topology()

    # Removing tmp dirs and files, once the topology is deleted
    try:
        os.system("rm -rf {}".format(TMPDIR))
    except IOError as (errno, strerror):
        logger.error("I/O error({0}): {1}".format(errno, strerror))


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

    try:
        for c_router, c_data in topo.iteritems():
            interface_data = []
            for destRouterLink, data in sorted(c_data["links"].iteritems()):
                # Loopback interfaces
                if "type" in data and data["type"] == "loopback":
                    interface_name = destRouterLink
                else:
                    interface_name = data["interface"]
                interface_data.append("interface {}\n".format(
                    str(interface_name)
                ))
                if "ipv4" in data:
                    intf_addr = c_data["links"][destRouterLink]["ipv4"]
                    interface_data.append("ip address {}\n".format(
                        intf_addr
                    ))
                if "ipv6" in data:
                    intf_addr = c_data["links"][destRouterLink]["ipv6"]
                    interface_data.append("ipv6 address {}\n".format(
                        intf_addr
                    ))
            result = create_common_configuration(tgen, c_router,
                                                 interface_data,
                                                 "interface_config",
                                                 build=build)
    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    return result

