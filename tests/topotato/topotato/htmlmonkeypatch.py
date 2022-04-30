#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2018-2021  David Lamparter for NetDEF, Inc.
"""
Monkey patch for pytest-html to add binary attachment support
"""

from pytest_html import extras, result, html_report
# pylint: disable=import-error,no-name-in-module
from py.xml import html

class ResultMonkey(result.TestResult):
    _orig_append_extra_html = result.TestResult.append_extra_html

    def append_extra_html(self, extra, extra_index, test_index):
        if extra.get("format_type") != extras.FORMAT_BINARY:
            return ResultMonkey._orig_append_extra_html(self, extra, extra_index, test_index)

        content = extra.get("content")
        if self.self_contained:
            href = self._data_uri(content, mime_type=extra.get("mime_type"))
        else:
            href = self.create_asset(
                content, extra_index, test_index, extra.get("extension"), "wb"
            )

        self.links_html.append(
            html.a(
                extra.get("name"),
                class_=extra.get("format_type"),
                href=href,
                target="_blank",
            )
        )
        self.links_html.append(" ")
        return None

    @classmethod
    def apply(cls):
        if hasattr(extras, 'FORMAT_BINARY'):
            return

        extras.FORMAT_BINARY = "binary"
        result.TestResult.append_extra_html = cls.append_extra_html

class HTMLTouchupMonkey:
    html_final_hook = lambda x: x

    def __init__(self):
        pass

    def html(self, *args, **kwargs):
        result = html.html(*args, **kwargs)
        return self.__class__.html_final_hook(result)

    def __getattr__(self, attrname):
        return getattr(html, attrname)


html_report.html = HTMLTouchupMonkey()
