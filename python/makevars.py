#
# helper class to grab variables from FRR's Makefile
#

import os
import subprocess

class MakeVars(object):
    '''
    makevars['FOO_CFLAGS'] gets you "FOO_CFLAGS" from Makefile
    '''
    def __init__(self):
        self._data = dict()

    def getvars(self, varlist):
        '''
        get a batch list of variables from make.  faster than individual calls.
        '''
        rdfd, wrfd = os.pipe()

        shvars = ['shvar-%s' % s for s in varlist]
        make = subprocess.Popen(['make', '-s', 'VARFD=%d' % wrfd] + shvars, pass_fds = [wrfd])
        os.close(wrfd)
        data = b''

        rdf = os.fdopen(rdfd, 'rb')
        while True:
            rdata = rdf.read()
            if len(rdata) == 0:
                break
            data += rdata

        del rdf
        make.wait()

        data = data.decode('US-ASCII').strip().split('\n')
        for row in data:
            k, v = row.split('=', 1)
            v = v[1:-1]
            self._data[k] = v

    def __getitem__(self, k):
        if k not in self._data:
            self.getvars([k])
        return self._data[k]

    def get(self, k, defval = None):
        if k not in self._data:
            self.getvars([k])
        return self._data[k] or defval
