#!/usr/bin/python

import os
import sys

# take a default Snort config file and
# clean it up so the Dalton Agents won't
# throw errors

def usage_and_exit(msg=None):
    if msg:
        print "ERROR: %s\n" % msg
    print "Usage:"
    print "python %s in-file out-file" % (sys.argv[0])
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
            # remove reputation preprocessor
            while clean_line.endswith("\\"):
                clean_line = next(lines).rstrip('\r\n')
            continue
        if clean_line == "ipvar HOME_NET any":
            # ET ruleset will barf on this because of !any rules
            line = line.replace("any", r"[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]")
        fh.write(line)
    except StopIteration:
        break
fh.close()
