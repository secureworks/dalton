#!/usr/bin/python

# Copyright 2017 Secureworks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import sys

"""
Takes a default Snort config file and clean
it up so the Dalton Agents won't throw
 errors. Also tweak it to my preferences.
"""

def usage_and_exit(msg=None):
    if msg:
        print "\nERROR: %s\n" % msg
    print "Usage:"
    print "python %s <in-file> <out-file>\n" % (sys.argv[0])
    sys.exit(1)

if len(sys.argv) < 3:
    usage_and_exit("not enough arguments.")

infile = sys.argv[1]
outfile = sys.argv[2]

if not os.path.isfile(infile):
    usage_and_exit("ERROR: in-file does not exist.")
#if os.path.isfile(outfile):
#    usage_and_exit("ERROR: out-file already not exist. Not going to overwrite.")

fh = open(infile, 'rb')
config = fh.readlines()
fh.close

fh = open(outfile, 'wb')
lines = iter(config)
while True:
    try:
        line = next(lines)
        clean_line = line.rstrip('\r\n')
        if clean_line.startswith("include ") and clean_line.endswith(".rules"):
            # remove all rule includes
            continue
        if clean_line.startswith("preprocessor reputation:"):
            # comment out reputation preprocessor
            #  (black/white list file don't exist and Snort will error)
            while clean_line.endswith("\\"):
                line = "# %s" % line
                fh.write(line)
                line = next(lines)
                clean_line = line.rstrip('\r\n')
            line = "# %s" % line
            fh.write(line)
            continue
        if clean_line == "ipvar HOME_NET any":
            # ET ruleset will barf on this because of !any rules
            line = line.replace("any", r"[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]")
        if clean_line.startswith("preprocessor http_inspect_server: "):
            # add some options to http_inspect_server
            options = ["enable_xff", "log_uri","log_hostname"]
            while clean_line.endswith("\\"):
                for option in options:
                    if option in clean_line:
                        options.remove(option)
                fh.write(line)
                line = next(lines)
                clean_line = line.rstrip('\r\n')
            # using \n instead of \r\n
            line = "%s %s\n" % (clean_line, ' '.join(options))
            fh.write(line)
            continue
        fh.write(line)
    except StopIteration:
        break
fh.close()
