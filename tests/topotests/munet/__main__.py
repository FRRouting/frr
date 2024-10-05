# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# September 2 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021, LabN Consulting, L.L.C.
#
"""The main function for standalone operation."""
import argparse
import asyncio
import logging
import logging.config
import os
import subprocess
import sys

from . import cli
from . import parser
from .args import add_launch_args
from .base import get_event_loop
from .cleanup import cleanup_previous
from .cleanup import is_running_in_rundir
from .compat import PytestConfig


logger = None


async def forever():
    while True:
        await asyncio.sleep(3600)


async def run_and_wait(args, unet):
    tasks = []

    if not args.topology_only:
        # add the cmd.wait()s returned from unet.run()
        tasks += await unet.run()

    if sys.stdin.isatty() and not args.no_cli:
        # Run an interactive CLI
        task = cli.async_cli(unet)
    else:
        if args.no_wait:
            logger.info("Waiting for all node cmd to complete")
            task = asyncio.gather(*tasks, return_exceptions=True)
        else:
            logger.info("Waiting on signal to exit")
            task = asyncio.create_task(forever())
            task = asyncio.gather(task, *tasks, return_exceptions=True)

    try:
        await task
    finally:
        # Basically we are canceling tasks from unet.run() which are just async calls to
        # node.cmd_p.wait() so we've stopped waiting for them to complete, but not
        # actually canceld/killed the cmd_p process.
        for task in tasks:
            task.cancel()


async def async_main(args, config):
    status = 3

    # Setup the namespaces and network addressing.

    unet = await parser.async_build_topology(
        config, rundir=args.rundir, args=args, pytestconfig=PytestConfig(args)
    )
    logger.info("Topology up: rundir: %s", unet.rundir)

    try:
        status = await run_and_wait(args, unet)
    except KeyboardInterrupt:
        logger.info("Exiting, received KeyboardInterrupt in async_main")
    except asyncio.CancelledError as ex:
        logger.info("task canceled error: %s cleaning up", ex)
    except Exception as error:
        logger.info("Exiting, unexpected exception %s", error, exc_info=True)
    else:
        logger.info("Exiting normally")

    logger.debug("main: async deleting")
    try:
        await unet.async_delete()
    except KeyboardInterrupt:
        status = 2
        logger.warning("Received KeyboardInterrupt while cleaning up.")
    except Exception as error:
        status = 2
        logger.info("Deleting, unexpected exception %s", error, exc_info=True)
    return status


def main(*args):
    ap = argparse.ArgumentParser(args)
    cap = ap.add_argument_group(title="Config", description="config related options")

    cap.add_argument("-c", "--config", help="config file (yaml, toml, json, ...)")
    cap.add_argument(
        "-d", "--rundir", help="runtime directory for tempfiles, logs, etc"
    )
    cap.add_argument(
        "--kinds-config",
        help="kinds config file, overrides default search (yaml, toml, json, ...)",
    )
    cap.add_argument(
        "--project-root", help="directory to stop searching for kinds config at"
    )

    rap = ap.add_argument_group(title="Runtime", description="runtime related options")
    add_launch_args(rap.add_argument)

    # Move to munet.args?
    rap.add_argument(
        "-C",
        "--cleanup",
        action="store_true",
        help="Remove the entire rundir (not just node subdirs) prior to running.",
    )
    # Move to munet.args?
    rap.add_argument(
        "--topology-only",
        action="store_true",
        help="Do not run any node commands",
    )
    rap.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the config against the schema definition",
    )
    rap.add_argument("--unshare-inline", action="store_true", help=argparse.SUPPRESS)

    rap.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    rap.add_argument(
        "-V", "--version", action="store_true", help="print the verison number and exit"
    )

    eap = ap.add_argument_group(title="Uncommon", description="uncommonly used options")
    eap.add_argument("--log-config", help="logging config file (yaml, toml, json, ...)")
    eap.add_argument(
        "--kill",
        action="store_true",
        help="Kill previous running processes using same rundir and exit",
    )
    eap.add_argument("--no-kill", action="store_true", help=argparse.SUPPRESS)
    eap.add_argument(
        "--no-cli", action="store_true", help="Do not run the interactive CLI"
    )
    eap.add_argument("--no-wait", action="store_true", help="Exit after commands")

    args = ap.parse_args()

    if args.version:
        from importlib import metadata  # pylint: disable=C0415

        print(metadata.version("munet"))
        sys.exit(0)

    rundir = args.rundir if args.rundir else "/tmp/munet"
    rundir = os.path.abspath(rundir)
    args.rundir = rundir

    if args.kill:
        logging.info("Killing any previous run using rundir: {rundir}")
        cleanup_previous(args.rundir)
    elif is_running_in_rundir(args.rundir):
        logging.fatal(
            "Munet processes using rundir: %s, use `--kill` to cleanup first", rundir
        )
        return 1

    if args.cleanup:
        if os.path.exists(rundir):
            if not os.path.exists(f"{rundir}/config.json"):
                logging.critical(
                    'unsafe: won\'t clean up rundir "%s" as '
                    "previous config.json not present",
                    rundir,
                )
                sys.exit(1)
            else:
                subprocess.run(["/usr/bin/rm", "-rf", rundir], check=True)

    if args.kill:
        return 0

    subprocess.run(f"mkdir -p {rundir} && chmod 755 {rundir}", check=True, shell=True)
    os.environ["MUNET_RUNDIR"] = rundir

    parser.setup_logging(args)

    global logger  # pylint: disable=W0603
    logger = logging.getLogger("munet")

    config = parser.get_config(args.config)
    logger.info("Loaded config from %s", config["config_pathname"])
    if not config["topology"]["nodes"]:
        logger.critical("No nodes defined in config file")
        return 1

    loop = None
    status = 4
    try:
        parser.validate_config(config, logger, args)
        if args.validate_only:
            return 0
        # Executes the cmd for each node.
        loop = get_event_loop()
        status = loop.run_until_complete(async_main(args, config))
    except KeyboardInterrupt:
        logger.info("Exiting, received KeyboardInterrupt in main")
    except Exception as error:
        logger.info("Exiting, unexpected exception %s", error, exc_info=True)
    finally:
        if loop:
            loop.close()

    return status


if __name__ == "__main__":
    exit_status = main()
    sys.exit(exit_status)
