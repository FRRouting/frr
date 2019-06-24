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

import os

from lib.topolog import logger, logger_config
from lib.topogen import TopoRouter


# Creating tmp dir with testsuite name to avoid conflict condition when
# multiple testsuites run together. All temporary files would be created
# in this dir and this dir would be removed once testsuite run is
# completed
LOGDIR = "/tmp/topotests/"
TMPDIR = None


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

