# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# September 30 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021, LabN Consulting, L.L.C.
#
"""A module that implements the standalone parser."""
import asyncio
import importlib.resources
import json
import logging
import logging.config
import os
import subprocess
import sys
import tempfile

from pathlib import Path


try:
    import jsonschema  # pylint: disable=C0415
    import jsonschema.validators  # pylint: disable=C0415

    from jsonschema.exceptions import ValidationError  # pylint: disable=C0415
except ImportError:
    jsonschema = None

from .config import list_to_dict_with_key
from .native import Munet


def get_schema():
    if get_schema.schema is None:
        with importlib.resources.path("munet", "munet-schema.json") as datapath:
            search = [str(datapath.parent)]
        get_schema.schema = get_config(basename="munet-schema", search=search)
    return get_schema.schema


get_schema.schema = None

project_root_contains = [
    ".git",
    "pyproject.toml",
    "tox.ini",
    "setup.cfg",
    "setup.py",
    "pytest.ini",
    ".projectile",
]


def is_project_root(path: Path) -> bool:

    for contains in project_root_contains:
        if path.joinpath(contains).exists():
            return True
    return False


def find_project_root(config_path: Path, project_root=None):
    if project_root is not None:
        project_root = Path(project_root)
        if project_root in config_path.parents:
            return project_root
        logging.warning(
            "project_root %s is not a common ancestor of config file %s",
            project_root,
            config_path,
        )
        return config_path.parent
    for ppath in config_path.parents:
        if is_project_root(ppath):
            return ppath
    return config_path.parent


def get_config(pathname=None, basename="munet", search=None, logf=logging.debug):

    cwd = os.getcwd()

    if not search:
        search = [cwd]
    elif isinstance(search, (str, Path)):
        search = [search]

    if pathname:
        pathname = os.path.join(cwd, pathname)
        if not os.path.exists(pathname):
            raise FileNotFoundError(pathname)
    else:
        for d in search:
            logf("%s", f'searching in "{d}" for "{basename}".{{yaml, toml, json}}')
            for ext in ("yaml", "toml", "json"):
                pathname = os.path.join(d, basename + "." + ext)
                if os.path.exists(pathname):
                    logf("%s", f'Found "{pathname}"')
                    break
            else:
                continue
            break
        else:
            raise FileNotFoundError(basename + ".{json,toml,yaml} in " + f"{search}")

    _, ext = pathname.rsplit(".", 1)

    if ext == "json":
        config = json.load(open(pathname, encoding="utf-8"))
    elif ext == "toml":
        import toml  # pylint: disable=C0415

        config = toml.load(pathname)
    elif ext == "yaml":
        import yaml  # pylint: disable=C0415

        config = yaml.safe_load(open(pathname, encoding="utf-8"))
    else:
        raise ValueError("Filename does not end with (.json|.toml|.yaml)")

    config["config_pathname"] = os.path.realpath(pathname)
    return config


def setup_logging(args, config_base="logconf"):
    # Create rundir and arrange for future commands to run in it.

    # Change CWD to the rundir prior to parsing config
    old = os.getcwd()
    os.chdir(args.rundir)
    try:
        search = [old]
        with importlib.resources.path("munet", config_base + ".yaml") as datapath:
            search.append(str(datapath.parent))

        def logf(msg, *p, **k):
            if args.verbose:
                print("PRELOG: " + msg % p, **k, file=sys.stderr)

        config = get_config(args.log_config, config_base, search, logf=logf)
        pathname = config["config_pathname"]
        del config["config_pathname"]

        if "info_console" in config["handlers"]:
            # mutest case
            if args.verbose > 1:
                config["handlers"]["console"]["level"] = "DEBUG"
                config["handlers"]["info_console"]["level"] = "DEBUG"
            elif args.verbose:
                config["handlers"]["console"]["level"] = "INFO"
                config["handlers"]["info_console"]["level"] = "DEBUG"
        elif args.verbose:
            # munet case
            config["handlers"]["console"]["level"] = "DEBUG"

        # add the rundir path to the filenames
        for v in config["handlers"].values():
            filename = v.get("filename")
            if not filename:
                continue
            v["filename"] = os.path.join(args.rundir, filename)

        logging.config.dictConfig(dict(config))
        logging.info("Loaded logging config %s", pathname)

        return config
    finally:
        os.chdir(old)


def append_hosts_files(unet, netname):
    if not netname:
        return

    entries = []
    for name in ("munet", *list(unet.hosts)):
        if name == "munet":
            node = unet.switches[netname]
            ifname = None
        else:
            node = unet.hosts[name]
            if not hasattr(node, "_intf_addrs"):
                continue
            ifname = node.get_ifname(netname)

        for b in (False, True):
            ifaddr = node.get_intf_addr(ifname, ipv6=b)
            if ifaddr and hasattr(ifaddr, "ip"):
                entries.append((name, ifaddr.ip))

    for name in ("munet", *list(unet.hosts)):
        node = unet if name == "munet" else unet.hosts[name]
        if not hasattr(node, "rundir"):
            continue
        with open(os.path.join(node.rundir, "hosts.txt"), "a+", encoding="ascii") as hf:
            hf.write("\n")
            for e in entries:
                hf.write(f"{e[1]}\t{e[0]}\n")


def validate_config(config, logger, args):
    if jsonschema is None:
        logger.debug("No validation w/o jsonschema module")
        return True

    old = os.getcwd()
    if args:
        os.chdir(args.rundir)

    try:
        validator = jsonschema.validators.Draft202012Validator(get_schema())
        validator.validate(instance=config)
        logger.debug("Validated %s", config["config_pathname"])
        return True
    except FileNotFoundError as error:
        logger.info("No schema found: %s", error)
        return False
    except ValidationError as error:
        logger.info("Validation failed: %s", error)
        return False
    finally:
        if args:
            os.chdir(old)


def load_kinds(args, search=None):
    # Change CWD to the rundir prior to parsing config
    cwd = os.getcwd()
    if args:
        os.chdir(args.rundir)

    args_config = args.kinds_config if args and hasattr(args, "kinds_config") else None
    try:
        if search is None:
            search = [cwd]
        with importlib.resources.path("munet", "kinds.yaml") as datapath:
            search.insert(0, str(datapath.parent))

        configs = []
        if args_config:
            configs.append(get_config(args_config, "kinds", search=[]))
        else:
            # prefer directories at the front of the list
            for kdir in search:
                try:
                    configs.append(get_config(basename="kinds", search=[kdir]))
                except FileNotFoundError:
                    continue

        kinds = {}
        for config in configs:
            # XXX need to fix the issue with `connections: ["net0"]` not validating
            # if jsonschema is not None:
            #     validator = jsonschema.validators.Draft202012Validator(get_schema())
            #     validator.validate(instance=config)

            kinds_list = config.get("kinds", [])
            kinds_dict = list_to_dict_with_key(kinds_list, "name")
            if kinds_dict:
                logging.info("Loading kinds config from %s", config["config_pathname"])
                if "kinds" in kinds:
                    kinds["kinds"].update(**kinds_dict)
                else:
                    kinds["kinds"] = kinds_dict

            cli_list = config.get("cli", {}).get("commands", [])
            if cli_list:
                logging.info("Loading cli comands from %s", config["config_pathname"])
                if "cli" not in kinds:
                    kinds["cli"] = {}
                if "commands" not in kinds["cli"]:
                    kinds["cli"]["commands"] = []
                kinds["cli"]["commands"].extend(cli_list)

        return kinds
    except FileNotFoundError as error:
        # if we have kinds in args but the file doesn't exist, raise the error
        if args_config is not None:
            raise error
        return {}
    finally:
        if args:
            os.chdir(cwd)


async def async_build_topology(
    config=None,
    logger=None,
    rundir=None,
    args=None,
    unshare_inline=False,
    pytestconfig=None,
    search_root=None,
    top_level_pidns=True,
):

    if not rundir:
        rundir = tempfile.mkdtemp(prefix="unet")
    subprocess.run(f"mkdir -p {rundir} && chmod 755 {rundir}", check=True, shell=True)

    isolated = not args.host if args else True
    if not config:
        config = get_config(basename="munet")

    # create search directories from common root if given
    cpath = Path(config["config_pathname"]).absolute()
    project_root = args.project_root if args and hasattr(args, "project_root") else None
    if not search_root:
        search_root = find_project_root(cpath, project_root)
    if not search_root:
        search = [cpath.parent]
    else:
        search_root = Path(search_root).absolute()
        if search_root in cpath.parents:
            search = list(cpath.parents)
            if remcount := len(search_root.parents):
                search = search[0:-remcount]

    # load kinds along search path and merge into config
    kinds = load_kinds(args, search=search)
    config_kinds_dict = list_to_dict_with_key(config.get("kinds", []), "name")
    config["kinds"] = {**kinds.get("kinds", {}), **config_kinds_dict}

    # mere CLI command from kinds into config as well.
    kinds_cli_list = kinds.get("cli", {}).get("commands", [])
    config_cli_list = config.get("cli", {}).get("commands", [])
    if config_cli_list:
        if kinds_cli_list:
            config_cli_list.extend(list(kinds_cli_list))
    elif kinds_cli_list:
        if "cli" not in config:
            config["cli"] = {}
        if "commands" not in config["cli"]:
            config["cli"]["commands"] = []
        config["cli"]["commands"].extend(list(kinds_cli_list))

    unet = Munet(
        rundir=rundir,
        config=config,
        pytestconfig=pytestconfig,
        isolated=isolated,
        pid=top_level_pidns,
        unshare_inline=(
            args.unshare_inline
            if args and hasattr(args, "unshare_inline")
            else unshare_inline
        ),
        logger=logger,
    )

    try:
        await unet._async_build(logger)  # pylint: disable=W0212
    except Exception as error:
        logging.critical("Failure building munet topology: %s", error, exc_info=True)
        await unet.async_delete()
        raise
    except KeyboardInterrupt:
        await unet.async_delete()
        raise

    topoconf = config.get("topology")
    if not topoconf:
        return unet

    dns_network = topoconf.get("dns-network")
    if dns_network:
        append_hosts_files(unet, dns_network)

    # Write our current config to the run directory
    with open(f"{unet.rundir}/config.json", "w", encoding="utf-8") as f:
        json.dump(unet.config, f, indent=2)

    return unet


def build_topology(config=None, logger=None, rundir=None, args=None, pytestconfig=None):
    return asyncio.run(async_build_topology(config, logger, rundir, args, pytestconfig))
