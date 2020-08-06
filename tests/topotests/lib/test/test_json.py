#!/usr/bin/env python

#
# test_json.py
# Tests for library function: json_cmp().
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Tests for the json_cmp() function.
"""

import os
import sys
import pytest

# Save the Current Working Directory to find lib files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
from lib.topotest import json_cmp


def test_json_intersect_true():
    "Test simple correct JSON intersections"

    dcomplete = {
        "i1": "item1",
        "i2": "item2",
        "i3": "item3",
        "i100": "item4",
    }

    dsub1 = {
        "i1": "item1",
        "i3": "item3",
    }
    dsub2 = {
        "i1": "item1",
        "i2": "item2",
    }
    dsub3 = {
        "i100": "item4",
        "i2": "item2",
    }
    dsub4 = {
        "i50": None,
        "i100": "item4",
    }

    assert json_cmp(dcomplete, dsub1) is None
    assert json_cmp(dcomplete, dsub2) is None
    assert json_cmp(dcomplete, dsub3) is None
    assert json_cmp(dcomplete, dsub4) is None


def test_json_intersect_false():
    "Test simple incorrect JSON intersections"

    dcomplete = {
        "i1": "item1",
        "i2": "item2",
        "i3": "item3",
        "i100": "item4",
    }

    # Incorrect value for 'i1'
    dsub1 = {
        "i1": "item3",
        "i3": "item3",
    }
    # Non-existing key 'i5'
    dsub2 = {
        "i1": "item1",
        "i5": "item2",
    }
    # Key should not exist
    dsub3 = {
        "i100": None,
    }

    assert json_cmp(dcomplete, dsub1) is not None
    assert json_cmp(dcomplete, dsub2) is not None
    assert json_cmp(dcomplete, dsub3) is not None


def test_json_intersect_multilevel_true():
    "Test multi level correct JSON intersections"

    dcomplete = {
        "i1": "item1",
        "i2": "item2",
        "i3": {"i100": "item100",},
        "i4": {
            "i41": {"i411": "item411",},
            "i42": {"i421": "item421", "i422": "item422",},
        },
    }

    dsub1 = {
        "i1": "item1",
        "i3": {"i100": "item100",},
        "i10": None,
    }
    dsub2 = {
        "i1": "item1",
        "i2": "item2",
        "i3": {},
    }
    dsub3 = {
        "i2": "item2",
        "i4": {"i41": {"i411": "item411",}, "i42": {"i422": "item422", "i450": None,}},
    }
    dsub4 = {"i2": "item2", "i4": {"i41": {}, "i42": {"i450": None,}}}
    dsub5 = {"i2": "item2", "i3": {"i100": "item100",}, "i4": {"i42": {"i450": None,}}}

    assert json_cmp(dcomplete, dsub1) is None
    assert json_cmp(dcomplete, dsub2) is None
    assert json_cmp(dcomplete, dsub3) is None
    assert json_cmp(dcomplete, dsub4) is None
    assert json_cmp(dcomplete, dsub5) is None


def test_json_intersect_multilevel_false():
    "Test multi level incorrect JSON intersections"

    dcomplete = {
        "i1": "item1",
        "i2": "item2",
        "i3": {"i100": "item100",},
        "i4": {
            "i41": {"i411": "item411",},
            "i42": {"i421": "item421", "i422": "item422",},
        },
    }

    # Incorrect sub-level value
    dsub1 = {
        "i1": "item1",
        "i3": {"i100": "item00",},
        "i10": None,
    }
    # Inexistent sub-level
    dsub2 = {
        "i1": "item1",
        "i2": "item2",
        "i3": None,
    }
    # Inexistent sub-level value
    dsub3 = {
        "i1": "item1",
        "i3": {"i100": None,},
    }
    # Inexistent sub-sub-level value
    dsub4 = {"i4": {"i41": {"i412": "item412",}, "i42": {"i421": "item421",}}}
    # Invalid sub-sub-level value
    dsub5 = {"i4": {"i41": {"i411": "item411",}, "i42": {"i421": "item420000",}}}
    # sub-sub-level should be value
    dsub6 = {"i4": {"i41": {"i411": "item411",}, "i42": "foobar",}}

    assert json_cmp(dcomplete, dsub1) is not None
    assert json_cmp(dcomplete, dsub2) is not None
    assert json_cmp(dcomplete, dsub3) is not None
    assert json_cmp(dcomplete, dsub4) is not None
    assert json_cmp(dcomplete, dsub5) is not None
    assert json_cmp(dcomplete, dsub6) is not None


def test_json_with_list_sucess():
    "Test successful json comparisons that have lists."

    dcomplete = {
        "list": [{"i1": "item 1", "i2": "item 2",}, {"i10": "item 10",},],
        "i100": "item 100",
    }

    # Test list type
    dsub1 = {
        "list": [],
    }
    # Test list correct list items
    dsub2 = {
        "list": [{"i1": "item 1",},],
        "i100": "item 100",
    }
    # Test list correct list size
    dsub3 = {
        "list": [{}, {},],
    }

    assert json_cmp(dcomplete, dsub1) is None
    assert json_cmp(dcomplete, dsub2) is None
    assert json_cmp(dcomplete, dsub3) is None


def test_json_with_list_failure():
    "Test failed json comparisons that have lists."

    dcomplete = {
        "list": [{"i1": "item 1", "i2": "item 2",}, {"i10": "item 10",},],
        "i100": "item 100",
    }

    # Test list type
    dsub1 = {
        "list": {},
    }
    # Test list incorrect list items
    dsub2 = {
        "list": [{"i1": "item 2",},],
        "i100": "item 100",
    }
    # Test list correct list size
    dsub3 = {
        "list": [{}, {}, {},],
    }

    assert json_cmp(dcomplete, dsub1) is not None
    assert json_cmp(dcomplete, dsub2) is not None
    assert json_cmp(dcomplete, dsub3) is not None


def test_json_list_start_success():
    "Test JSON encoded data that starts with a list that should succeed."

    dcomplete = [
        {"id": 100, "value": "abc",},
        {"id": 200, "value": "abcd",},
        {"id": 300, "value": "abcde",},
    ]

    dsub1 = [{"id": 100, "value": "abc",}]

    dsub2 = [{"id": 100, "value": "abc",}, {"id": 200, "value": "abcd",}]

    dsub3 = [{"id": 300, "value": "abcde",}]

    dsub4 = []

    dsub5 = [{"id": 100,}]

    assert json_cmp(dcomplete, dsub1) is None
    assert json_cmp(dcomplete, dsub2) is None
    assert json_cmp(dcomplete, dsub3) is None
    assert json_cmp(dcomplete, dsub4) is None
    assert json_cmp(dcomplete, dsub5) is None


def test_json_list_start_failure():
    "Test JSON encoded data that starts with a list that should fail."

    dcomplete = [
        {"id": 100, "value": "abc"},
        {"id": 200, "value": "abcd"},
        {"id": 300, "value": "abcde"},
    ]

    dsub1 = [{"id": 100, "value": "abcd",}]

    dsub2 = [{"id": 100, "value": "abc",}, {"id": 200, "value": "abc",}]

    dsub3 = [{"id": 100, "value": "abc",}, {"id": 350, "value": "abcde",}]

    dsub4 = [{"value": "abcx",}, {"id": 300, "value": "abcde",}]

    assert json_cmp(dcomplete, dsub1) is not None
    assert json_cmp(dcomplete, dsub2) is not None
    assert json_cmp(dcomplete, dsub3) is not None
    assert json_cmp(dcomplete, dsub4) is not None


if __name__ == "__main__":
    sys.exit(pytest.main())
