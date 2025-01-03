#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2023  David Lamparter for NetDEF, Inc.
"""
Jinja2 python-inline template helpers
"""

# TODO: write self-tests for this!

import sys
import inspect
import ast
from typing import (
    Any,
    Dict,
    Iterable,
    List,
    MutableMapping,
    Optional,
    Tuple,
    Type,
)

import jinja2


class _ConstFinder(ast.NodeVisitor):
    """
    Locate a string's source in python files.

    Parses the python source using the ast module and tries to find a string
    constant with a matching value.  Unfortunately, there's no better way to
    get source locations for inline jinja2 templates.
    """

    _search: str
    _found: List[ast.Constant]

    def __init__(self, search: str):
        self._search = search
        self._found = []

    def visit_Constant(self, node: ast.Constant):
        if node.value == self._search:
            self._found.append(node)

    def _reframe(self, filename: str) -> Tuple[Optional[str], str]:
        """
        Realign the search text to match the source location found, if any.

        This just adds a bunch of '##-' comment lines to make line numbers
        match up with where the text was found.
        """
        if len(self._found) != 1:
            return None, self._search

        node = self._found[0]
        return (
            filename,
            (node.lineno - 1) * "##-\n" + (node.col_offset + 3) * " " + self._search,
        )

    @classmethod
    def search(cls, src: str, filename: str, text: str) -> Tuple[Optional[str], str]:
        """
        Do "the thing", main entry point to this class.

        May return (None, text) if the template cannot be found.
        """
        self = cls(text)
        self.generic_visit(ast.parse(src, filename))
        return self._reframe(filename)


class InlineEnv(jinja2.Environment):
    """
    Customized jinja2 environment for use in topotato.

    Line comments are started with ``##``, line statements with ``#%``.
    """

    _templates: Dict[str, Tuple[Optional[str], str]]

    def __init__(self, *args, **kwargs):
        self._templates = {}

        kwargs.setdefault("line_comment_prefix", "#" + "#")
        kwargs.setdefault("line_statement_prefix", "#" + "%")
        kwargs.setdefault("autoescape", False)
        kwargs.setdefault("loader", jinja2.FunctionLoader(self._get_reg_template))

        super().__init__(*args, **kwargs)

    def _get_reg_template(self, name):
        if name not in self._templates:
            raise FileNotFoundError(name)

        filename, source = self._templates[name]
        return (source, filename, None)

    def register_template(self, name: str, source: str, call_depth=1):
        """
        Add template source so that it can be referenced with "extends".
        """
        frame = inspect.currentframe()
        for i in range(0, call_depth):
            if frame is None:
                raise RuntimeError(
                    f"invalid call depth {i}/{call_depth} for template setup"
                )
            frame = frame.f_back

        if frame is None:
            raise RuntimeError("invalid call depth for template setup")

        filename = frame.f_code.co_filename
        self._templates[name] = _ConstFinder.search(
            inspect.getsource(frame), filename, source
        )

    def register_templates(self, items: Iterable[Tuple[str, str]]):
        """
        Register multiple templates with :py:meth:`register_template`.
        """
        for name, source in items:
            self.register_template(name, source, 2)

    def compile_class_attr(
        self,
        cls: Type,
        attr: str,
        globals_: Optional[MutableMapping[str, Any]] = None,
        template_class: Optional[Type["jinja2.Template"]] = None,
    ):
        """
        Given a class (type) object, and an attribute name, load template.

        This hunts for the class actually defining the attribute named, and
        then attempts to set up filename and line number for jinja exceptions.

        :param cls: Class (type object) to operate on.  This normally should
           be the class itself, not an instance of it.
        :param attr: Attribute name to fetch from the class.
        """
        filename, source = None, getattr(cls, attr)
        assert isinstance(source, str)

        for base in inspect.getmro(cls):
            if attr in base.__dict__:
                module = sys.modules[base.__module__]
                if module.__file__ is not None:
                    filename, source = _ConstFinder.search(
                        inspect.getsource(module), module.__file__, source
                    )
                break
        else:
            raise RuntimeError(
                f"cannot find definition location for {cls.__name__}.{attr}"
            )

        gs = self.make_globals(globals_)
        template_class = template_class or self.template_class
        compiled = self.compile(source, filename=filename)
        return template_class.from_code(self, compiled, gs, None)
