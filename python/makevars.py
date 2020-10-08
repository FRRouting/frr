#
# helper class to grab variables from FRR's Makefile
#

import os
import subprocess
import re


class MakeVarsBase(object):
    """
    common code between MakeVars and MakeReVars
    """

    def __init__(self):
        self._data = dict()

    def __getitem__(self, k):
        if k not in self._data:
            self.getvars([k])
        return self._data[k]

    def get(self, k, defval=None):
        if k not in self._data:
            self.getvars([k])
        return self._data.get(k) or defval


class MakeVars(MakeVarsBase):
    """
    makevars['FOO_CFLAGS'] gets you "FOO_CFLAGS" from Makefile

    This variant works by invoking make as a subprocess, i.e. Makefile must
    be valid and working.  (This is sometimes a problem if depfiles have not
    been generated.)
    """

    def getvars(self, varlist):
        """
        get a batch list of variables from make.  faster than individual calls.
        """
        rdfd, wrfd = os.pipe()

        shvars = ["shvar-%s" % s for s in varlist]
        make = subprocess.Popen(
            ["make", "-s", "VARFD=%d" % wrfd] + shvars, pass_fds=[wrfd]
        )
        os.close(wrfd)
        data = b""

        rdf = os.fdopen(rdfd, "rb")
        while True:
            rdata = rdf.read()
            if len(rdata) == 0:
                break
            data += rdata

        del rdf
        make.wait()

        data = data.decode("US-ASCII").strip().split("\n")
        for row in data:
            k, v = row.split("=", 1)
            v = v[1:-1]
            self._data[k] = v


class MakeReVars(MakeVarsBase):
    """
    makevars['FOO_CFLAGS'] gets you "FOO_CFLAGS" from Makefile

    This variant works by regexing through Makefile.  This means the Makefile
    does not need to be fully working, but on the other hand it doesn't support
    fancy complicated make expressions.
    """

    var_re = re.compile(
        r"^([^=#\n\s]+)[ \t]*=[ \t]*([^#\n]*)(?:#.*)?$", flags=re.MULTILINE
    )
    repl_re = re.compile(r"\$(?:([A-Za-z])|\(([^\)]+)\))")

    def __init__(self, maketext):
        super(MakeReVars, self).__init__()
        self._vars = dict(self.var_re.findall(maketext.replace("\\\n", "")))

    def replacevar(self, match):
        varname = match.group(1) or match.group(2)
        return self._vars.get(varname, "")

    def getvars(self, varlist):
        for varname in varlist:
            if varname not in self._vars:
                continue

            val, prevval = self._vars[varname], None
            while val != prevval:
                prevval = val
                val = self.repl_re.sub(self.replacevar, val)

            self._data[varname] = val
