#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2022  David Lamparter for NetDEF, Inc.
"""
basic tests for topotato.generatorwrap
"""

import pytest
from topotato.generatorwrap import GeneratorChecks, GeneratorWrapper, GeneratorsUnused


def ref_gen_nowrap():
    yield 1
    sent_val = yield 2
    yield (sent_val or 2) + 1


ref_gen_wrap = GeneratorWrapper.apply(ref_gen_nowrap)


@pytest.fixture(params=[ref_gen_nowrap, ref_gen_wrap])
def both_gens(request):
    return request.param


def test_still_functional(both_gens):
    assert list(both_gens()) == [1, 2, 3]


def test_sending(both_gens):
    gen = both_gens()
    itr = iter(gen)
    assert next(itr) == 1
    assert itr.send(123) == 2
    assert itr.send(4) == 5
    with pytest.raises(StopIteration):
        next(itr)


def test_nofail(both_gens):
    with GeneratorChecks():
        gen = both_gens()
        assert list(gen) == [1, 2, 3]


def test_unwrapped_fail():
    with GeneratorChecks():
        ref_gen_nowrap()


def test_wrapped_fail():
    with pytest.raises(GeneratorsUnused):
        with GeneratorChecks():
            ref_gen_wrap()


def test_wrapped_multifail():
    with pytest.raises(GeneratorsUnused):
        with GeneratorChecks() as checks:
            ref_gen_wrap()
            ref_gen_wrap()
            assert len(checks._errs) == 2


class GeneratorMethod:
    @GeneratorWrapper.apply
    def gen1(self):
        yield 1

    @classmethod
    @GeneratorWrapper.apply
    def gen2(cls):
        yield 2

    @staticmethod
    @GeneratorWrapper.apply
    def gen3():
        yield 3


def test_method_wrap():
    assert list(GeneratorMethod().gen1()) == [1]
    assert list(GeneratorMethod.gen2()) == [2]
    assert list(GeneratorMethod.gen3()) == [3]
