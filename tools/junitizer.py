#!/usr/bin/python

# Converts varnish's testresults into a junit XML file

# Authors: Denes Matetelki <dmatetelki@varnish-software.com>, March 2018.
#          Espen Braastad <espen@varnish-software.com>, July 2019.

import __future__
from lxml import etree
import os
import re
import sys
import time

class TestCase:
    def __init__(self, name):
        self.name = name
        self.desc = None
        self.status = None
        self.time = None
        self.message = b''
        self.trace = b''
        self.vtc = None
        self.log = None
        self.trs = None
        self.group_log = False
        self.raw_assert = False

    def set_trs(self, trs):
        self.trs = trs
        with open(trs) as f:
            for line in f:
                # :test-result: PASS
                line = line.rstrip()
                if line == ":test-result: SKIP":
                    self.status = "skipped"
                    break

                if line == ':test-result: PASS':
                    self.status = "passed"
                    break

                self.status = "failure"

    def set_log(self, log):
        self.log = log
        with open(log, 'rb') as f:
            for line in f:
                # ---- c1    0.5 EXPECT resp.http.x-timestamp (Wed, 03 Jul 2019 22:07:11 GMT) ~ "..., .. ... .... ..:..:.. UTC" failed
                x = re.match(b'^.*EXPECT.*failed$', line)
                if x:
                    self.message = line
                    continue

                # *    top   0.0 SKIPPING test, lacking feature: persistent_storage

                x = re.match(b'^.*SKIPPING test.*', line)
                if x:
                    self.message = line
                    continue

                # #    top  TEST ./vmodtests/crypto/test37.vtc passed (1.816)
                x = re.match(b'^#\s+top\s+TEST.*\((\d+.\d+)\)', line)
                if x:
                    self.time = float(x.group(1))
                    continue

    def set_vtc_log(self, log):
        self.log = log
        with open(log, 'rb') as f:
            for line in f:
                if str(line).isspace():
                    continue

                # #    top  TEST ./vmodtests/crypto/test37.vtc passed (1.816)
                x = re.match(b'^#\s+top\s+TEST.*\((\d+.\d+)\)', line)
                if x:
                    self.time = float(x.group(1))

                if self.status == "failure":
                    # **** top   0.0 extmacro def bad_backend=127.0.0.1 42603
                    # **** top   0.0 macro def testdir=/workspace/bin/varnishtest/./tests
                    # ***  v1    0.0 CMD: cd ${pwd} && exec varnishd  -d -n /tmp/vtc.9953.32a794d0/v1 -l 2m -p auto_restart=off -p [...]
                    # ***  v1    0.1 debug|Linux,4.15.0-1052-aws,x86_64,-jnone,-sdefault,-sdefault,-hcritbit
                    # **** v1    0.2 CLI RX|Type 'start' to launch worker process.
                    # **** v1    0.2 CLI TX|\t\tdebug.store_ip(std.ip("9.9.9.*", "127.0.0.1 45419"));
                    # **** c1    0.9 http[ 4] |Date: Wed, 11 Dec 2019 23:48:16 GMT
                    # **** c1    0.9 http[ 5] |X-Varnish: 1001
                    # **** s2    1.3 txresp|^_`abcdefghijklmnopqrstuvwxyz{|}!"#$%&'()*+,-./0123456789:;<=>?[...]
                    # **** c10   1.3 body|jklmnopqrstuvwxyz{|}!"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJK[...]
                    # **** c1    0.8 chunk|01234567012345670123456701234567012345670123456701234567012345670123456701234567012345670123456[...]

                    x = re.match(b'^\s*\*+\s+[0-9A-z]+\s+\d+\.?\d*\s+(debug|CLI TX|CLI RX|extmacro|macro|CMD:\s*cd\s+|http\[\s*\d+\]|(body|txresp|chunk)\|[^\s].{62,})', line)
                    if not x:
                        self.trace = self.trace + line

                if self.status == "failure":
                    # **   v1    1.1 VCL compilation failed (as expected)
                    x = re.match(b'^\s*\*+\s+[0-9A-z]+\s+\d+\.?\d*\s+VCL compilation failed \(as expected\)', line)
                    if x:
                        self.message = b''
                        self.group_log = False
                        self.trace = self.trace + line
                        continue

                    # ---- v1    6.3 Not true: MSE_BOOK.book.c_insert_timeout (0) == 1 (1)
                    # ---- c1    0.5 EXPECT resp.http.x-timestamp (Wed, 03 Jul 2019 22:07:11 GMT) ~ "..., .. ... .... ..:..:.. UTC" failed

                    x = re.match(b'^\s*(\*|\-)+\s+[0-9A-z]+\s+\d+\.?\d*\s+(Not true:|.*EXPECT.*failed$)', line)
                    if x:
                        self.message = line
                        continue

                    # #    top  TEST ./vmodtests/vha6/test36.vtc TIMED OUT (kill -9)
                    x = re.match(b'^#\s+top\s+TEST.*TIMED OUT', line)
                    if x:
                        self.message = self.message + line
                        continue

                    # **** top   4.4 shell_out|---- v1    2.1 FAIL timeout waiting for CLI connection
                    # **** top   4.4 shell_out|---- v1    2.5 Unexpected panic
                    # **** pvha 12.3 stderr|vha_htc: Error (sRep2): http://127.0.0.1:45139/foo: Server returned nothing (no headers, no data)
                    x = re.match(b'^\s*(\*|\-)+\s+[0-9A-z]+\s+\d+\.?\d*\s+(shell_out\|----|stderr)', line)
                    if x:
                        self.message = self.message + line
                        continue

                    # *    diag  0.0 Assert error in vtc_log_emit(), vtc_log.c line 158:
                    # *    diag  0.0   Condition(vtclog_left > l) not true. (errno=0 Success)
                    x = re.match(b'^\s*(\*|\-)+\s+(diag)+\s+(\d)+(\.(\d)*)?\s+', line)
                    if x:
                        if self.group_log:
                            self.message = self.message + line
                        else:
                            self.message = line
                            self.group_log = True
                        continue

                    # **** v1    1.1 CLI RX|Message from VCC-compiler:
                    x = re.match(b'^\s*(\*|\-)+\s+[0-9A-z]+\s+\d+(\.(\d)*)?\s+(CLI RX\|Message from VCC-compiler)', line)
                    if x:
                        self.message = line
                        self.group_log = True
                        self.trace = self.trace + line
                        continue

                    # We must have hit one of the following first:
                    # *    diag  0.0 Assert error in vtc_log_emit(), vtc_log.c line 158:
                    # **** v1    1.1 CLI RX|Message from VCC-compiler:
                    if self.group_log:

                        # **** v1    0.1 CLI RX|Could not load VMOD utils
                        # **** v1    0.1 CLI RX|\tFile name: /home/andrew/code/v11/steven/lib/libvmod_utils/.libs/libvmod_utils.so
                        # **** v1    0.1 CLI RX|\tdlerror: /home/andrew/code/v11/steven/lib/libvmod_utils/.libs/libvmod_utils.so: undefined symbol: WS_Release
                        # **** v1    0.1 CLI RX|('<vcl.inline>' Line 5 Pos 16)
                        # **** v1    0.1 CLI RX|        import utils;
                        # **** v1    0.1 CLI RX|---------------#####-
                        # **** v1    0.1 CLI RX|
                        # **** v1    0.1 CLI RX|Running VCC-compiler failed, exited with 2
                        # **** v1    0.1 CLI RX|VCL compilation failed
                        x = re.match(b'^\s*(\*)+\s+[0-9A-z]+\s+\d+(\.\d*)?\s+CLI RX', line)
                        if x:
                            self.message = self.message + line
                            self.trace = self.trace + line
                            continue

                        # ---- c1    0.8 EXPECT resp.http.port8 (8080) == "9080" failed
                        # (all vtc_panics start with "----")
                        x = re.match(b'^\s*(\-){4,}', line)
                        if x:
                            self.message = self.message + line
                            self.group_log = False
                            continue

                        # #    top  TEST ./tests/r02645.vtc FAILED (2.283) signal=6
                        x = re.match(b'^#\s+top\s+TEST.*FAILED', line)
                        if x:
                            self.group_log = False
                            continue
                        else:
                            self.message = b''

                        self.group_log = False

                    # ---- c1    0.8 EXPECT resp.http.port8 (8080) == "9080" failed
                    # (all vtc_panics start with "----")
                    x = re.match(b'^\s*\-{4,}', line)
                    if x:
                        self.message = self.message + line
                        continue

                    x = re.match(b'^Assert error', line)
                    if x:
                        self.raw_assert = True
                        self.message = self.message + line
                        continue

                    if self.raw_assert:
                        self.message = self.message + line
                        continue

                # *    top   0.0 SKIPPING test, lacking feature: persistent_storage
                x = re.match(b'^.*SKIPPING test.*', line)
                if x:
                    self.message = line
                    continue

    def set_vtc(self, vtc):
        self.vtc = vtc
        with open(self.vtc, 'rb') as f:
            for line in f:
                if self.desc != None:
                    continue
                x = re.match(b'^\s*varnishtest\s*"(.+)"', line)
                if x:
                    self.desc = x.group(1)
                    continue

def getTestName(filepath):
    return os.path.splitext(filepath)[0]

def generate_xml(testcases):
    # Summary
    tests = 0
    failures = 0
    skipped = 0
    duration = 0
    for t in testcases.values():
        tests += 1
        if t.status == "failure":
            failures += 1
        if t.status == "skipped":
            skipped += 1
        if t.time != None:
            duration += t.time

    # Generate XML
    testsuites = etree.Element("testsuites")
    testsuites.set("tests", str(tests))
    testsuites.set("failures", str(failures))
    testsuites.set("skipped", str(skipped))
    testsuites.set("duration", str(duration))

    varnishtest = etree.SubElement(testsuites, "testsuite")
    varnishtest.set("name", "varnishtest")

    other = etree.SubElement(testsuites, "testsuite")
    other.set("name", "other")

    for t in testcases.values():
        if t.vtc == None:
            testcase = etree.SubElement(other, "testcase")
            testcase.set("name", t.name)
            testcase.set("file", t.name)
        else:
            testcase = etree.SubElement(varnishtest, "testcase")
            if t.desc == None:
                testcase.set("name", t.vtc)
            else:
                testcase.set("name", t.desc)

            testcase.set("file", t.vtc)

        if t.time != None:
            testcase.set("time", str(t.time))

        if t.status == "skipped":
            skipped = etree.SubElement(testcase, "skipped")
            if str(t.message).isspace():
                skipped.set("message", t.message)

        if t.status == "failure":
            failure = etree.SubElement(testcase, "failure")
            if not str(t.message).isspace():
                failure.set("message", t.message)
                if not str(t.trace).isspace():
                    t.trace = t.message + b'\n' + t.trace
                else:
                    t.trace = t.message
            if not str(t.trace).isspace():
                failure.text = t.trace

    tree = etree.ElementTree(testsuites)
    return tree

def main():
    start_time = time.time()
    if len(sys.argv) != 3:
        print("Usage: junitizer.py VCP_DIR OUT.xml\n" \
              "\t\tVCP_DIR is the directory containing the test results\n" \
              "\t\tOUT.xml is the output file following the junit xml format.\n")
        sys.exit(1)

    indir = str(sys.argv[1])
    outfile = str(sys.argv[2])

    testcases = {}

    trs_files = []
    log_files = []
    vtc_files = []

    for root, dirs, files in os.walk(indir):
        for f in files:
            if f.endswith(".trs"):
                    filepath = os.path.join(root, f)
                    trs_files.append(filepath)
            elif f.endswith(".log"):
                    filepath = os.path.join(root, f)
                    log_files.append(filepath)
            elif f.endswith(".vtc"):
                    filepath = os.path.join(root, f)
                    vtc_files.append(filepath)

    for filepath in trs_files:
        name = getTestName(filepath)
        t = TestCase(name)
        t.set_trs(filepath)
        testcases[name] = t

    for filepath in vtc_files:
        name = getTestName(filepath)
        if name in testcases:
            t = testcases[name]
            t.set_vtc(filepath)

    for filepath in log_files:
        name = getTestName(filepath)
        if name in testcases:
            t = testcases[name]

            if t.vtc != None:
                if str(t.vtc).endswith(".vtc"):
                    t.set_vtc_log(filepath)
                    continue
            t.set_log(filepath)

    xml = generate_xml(testcases)
    with open(outfile, 'wb+') as fp:
        fp.write(etree.tostring(xml, pretty_print=True))

    print("Converted test results in %.02f seconds" % (time.time() - start_time))

if __name__ == "__main__":
    main()
