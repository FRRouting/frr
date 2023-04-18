# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# June 25 2022, Christian Hopps <chopps@gmail.com>
#
# Copyright (c) 2021-2022, LabN Consulting, L.L.C.
#
"""A module that defines common configuration utility functions."""
import logging

from collections.abc import Iterable
from copy import deepcopy
from typing import overload


def find_with_kv(lst, k, v):
    if lst:
        for e in lst:
            if k in e and e[k] == v:
                return e
    return {}


def find_all_with_kv(lst, k, v):
    rv = []
    if lst:
        for e in lst:
            if k in e and e[k] == v:
                rv.append(e)
    return rv


def find_matching_net_config(name, cconf, oconf):
    p = find_all_with_kv(oconf.get("connections", {}), "to", name)
    if not p:
        return {}

    rname = cconf.get("remote-name", None)
    if not rname:
        return p[0]

    return find_with_kv(p, "name", rname)


def merge_using_key(a, b, k):
    # First get a dict of indexes in `a` for the key value of `k` in objects of `a`
    m = list(a)
    mi = {o[k]: i for i, o in enumerate(m)}
    for o in b:
        bkv = o[k]
        if bkv in mi:
            m[mi[bkv]] = o
        else:
            mi[bkv] = len(m)
            m.append(o)
    return m


def list_to_dict_with_key(lst, k):
    """Convert a YANG styl list of objects to dict of objects.

    This function converts a YANG style list of objects (dictionaries) to a plain python
    dictionary of objects (dictionaries).  The value for the supplied key for each
    object is used to store the object in the new diciontary.

    This only works for lists of objects which are keyed on a single contained value.

    Args:
      lst: a *list* of python dictionary objects.
      k: the key value contained in each dictionary object in the list.

    Returns:
      A dictionary of objects (dictionaries).
    """
    return {x[k]: x for x in (lst if lst else [])}


def config_to_dict_with_key(c, ck, k):
    """Convert the config item from a list of objects to dict.

    Use :py:func:`list_to_dict_with_key` to convert the list of objects
    at ``c[ck]`` to a dict of the objects using the key ``k``.

    Args:
      c: config dictionary
      ck: The key identifying the list of objects from ``c``.
      k: The key to pass to :py:func:`list_to_dict_with_key`.

    Returns:
      A dictionary of objects (dictionaries).
    """
    c[ck] = list_to_dict_with_key(c.get(ck, []), k)
    return c[ck]


@overload
def config_subst(config: str, **kwargs) -> str:
    ...


@overload
def config_subst(config: Iterable, **kwargs) -> Iterable:
    ...


def config_subst(config: Iterable, **kwargs) -> Iterable:
    if isinstance(config, str):
        if "%RUNDIR%/%NAME%" in config:
            config = config.replace("%RUNDIR%/%NAME%", "%RUNDIR%")
            logging.warning(
                "config '%RUNDIR%/%NAME%' should be changed to '%RUNDIR%' only, "
                "converting automatically for now."
            )
        for name, value in kwargs.items():
            config = config.replace(f"%{name.upper()}%", str(value))
    elif isinstance(config, Iterable):
        try:
            return {k: config_subst(config[k], **kwargs) for k in config}
        except (KeyError, TypeError):
            return [config_subst(x, **kwargs) for x in config]
    return config


def value_merge_deepcopy(s1, s2):
    """Merge values using deepcopy.

    Create a deepcopy of the result of merging the values from dicts ``s1`` and ``s2``.
    If a key exists in both ``s1`` and ``s2`` the value from ``s2`` is used."
    """
    d = {}
    for k, v in s1.items():
        if k in s2:
            d[k] = deepcopy(s2[k])
        else:
            d[k] = deepcopy(v)
    return d


def merge_kind_config(kconf, config):
    mergekeys = kconf.get("merge", [])
    config = deepcopy(config)
    new = deepcopy(kconf)
    for k in new:
        if k not in config:
            continue

        if k not in mergekeys:
            new[k] = config[k]
        elif isinstance(new[k], list):
            new[k].extend(config[k])
        elif isinstance(new[k], dict):
            new[k] = {**new[k], **config[k]}
        else:
            new[k] = config[k]
    for k in config:
        if k not in new:
            new[k] = config[k]
    return new
