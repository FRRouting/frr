# -*- coding: utf-8 -*-
# SPDX-License-Identifier: ISC
# Copyright (c) 2017 Vincent Bernat <bernat@luffy.cx>

from pygments.lexer import RegexLexer, bygroups
from pygments.token import Text, Comment, Keyword
from pygments.token import String, Number, Name


class FRRLexer(RegexLexer):
    name = "frr"
    aliases = ["frr"]
    tokens = {
        "root": [
            (r"^[ \t]*!.*?\n", Comment.Singleline),
            (r'"(\\\\|\\"|[^"])*"', String.Double),
            (
                r"[a-f0-9]*:[a-f0-9]*:[a-f0-9:]*(:\d+\.\d+\.\d+\.\d+)?(/\d+)?",
                Number,
            ),  # IPv6
            (r"\d+\.\d+\.\d+\.\d+(/\d+)?", Number),  # IPv4
            (r"^([ \t]*)(no[ \t]+)?([-\w]+)", bygroups(Text, Keyword, Name.Function)),
            (r"[ \t]+", Text),
            (r"\n", Text),
            (r"\d+", Number),
            (r"\S+", Text),
        ],
    }
