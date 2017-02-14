import frrtest
import re

re_okfail = re.compile(r'^(?:\x1b\[3[12]m)?(?P<ret>OK|failed)'.encode('utf8'),
                       re.MULTILINE)

class TestAspath(frrtest.TestMultiOut):
    program = './test_aspath'

    def _parsertest(self, line):
        if not hasattr(self, 'parserno'):
            self.parserno = -1
        self.parserno += 1

        self._onesimple("test %d" % self.parserno)
        self._okfail("%s:" % line, okfail=re_okfail)
        self._okfail("empty prepend %s:" % line, okfail=re_okfail)

    def _attrtest(self, line):
        if not hasattr(self, 'attrno'):
            self.attrno = -1
        self.attrno += 1

        self._onesimple("aspath_attr test %d" % self.attrno)
        self._okfail(line, okfail=re_okfail)

TestAspath.parsertest("seq1")
TestAspath.parsertest("seq2")
TestAspath.parsertest("seq3")
TestAspath.parsertest("seqset")
TestAspath.parsertest("seqset2")
TestAspath.parsertest("multi")
TestAspath.parsertest("confed")
TestAspath.parsertest("confed2")
TestAspath.parsertest("confset")
TestAspath.parsertest("confmulti")
TestAspath.parsertest("seq4")
TestAspath.parsertest("tripleseq1")
TestAspath.parsertest("someprivate")
TestAspath.parsertest("allprivate")
TestAspath.parsertest("long")
TestAspath.parsertest("seq1extra")
TestAspath.parsertest("empty")
TestAspath.parsertest("redundantset")
TestAspath.parsertest("reconcile_lead_asp")
TestAspath.parsertest("reconcile_new_asp")
TestAspath.parsertest("reconcile_confed")
TestAspath.parsertest("reconcile_start_trans")
TestAspath.parsertest("reconcile_start_trans4")
TestAspath.parsertest("reconcile_start_trans_error")
TestAspath.parsertest("redundantset2")
TestAspath.parsertest("zero-size overflow")
TestAspath.parsertest("zero-size overflow + valid segment")
TestAspath.parsertest("invalid segment type")

for i in range(10):
    TestAspath.okfail("prepend test %d" % i)
for i in range(5):
    TestAspath.okfail("aggregate test %d" % i)
for i in range(5):
    TestAspath.okfail("reconcile test %d" % i)
for _ in range(22):
    TestAspath.okfail("left cmp ")

TestAspath.okfail("empty_get_test")

TestAspath.attrtest("basic test")
TestAspath.attrtest("length too short")
TestAspath.attrtest("length too long")
TestAspath.attrtest("incorrect flag")
TestAspath.attrtest("as4_path, with as2 format data")
TestAspath.attrtest("as4, with incorrect attr length")
TestAspath.attrtest("basic 4-byte as-path")
TestAspath.attrtest("4b AS_PATH: too short")
TestAspath.attrtest("4b AS_PATH: too long")
TestAspath.attrtest("4b AS_PATH: too long2")
TestAspath.attrtest("4b AS_PATH: bad flags")
TestAspath.attrtest("4b AS4_PATH w/o AS_PATH")
TestAspath.attrtest("4b AS4_PATH: confed")
