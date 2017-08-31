#!/usr/bin/python
#
# Note: originally written to run on Python 2.4 and up without the need for
# non-standard libararies so that is why some things are written the way 
# they are. This is especially noticable (painful?) with the use of urllib2
# instead of urllib3 or Requests.
#

import os
import sys
import traceback
import urllib
import urllib2
import re
import time
import datetime
import glob
import shutil
try:
    # for Python v2.6
    import json
except ImportError:
    # for Python versions < v2.6
    import simplejson as json
import subprocess
import zipfile
import ConfigParser
from optparse import OptionParser
import struct
import socket

# urllib2 in Python < 2.6 doesn't support setting a timeout so doing it like this
socket.setdefaulttimeout(30)

''' returns full path to file if found on system '''
def find_file(name):
    ret_path = None
    try:
        # see if it is already in the path by using the 'which' command
        process = subprocess.Popen("which %s" % name, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        if stderr:
            raise
        else:
            ret_path = stdout.strip()
    except:
        # file not in PATH, try manually searching
        paths = ['/usr/sbin', '/usr/bin', '/usr/local/bin', '/usr/local/sbin']
        for path in paths:
            candidate = "%s/%s" % (path, name)
            if os.path.exists(candidate):
                ret_val = candidate
                break
    return ret_path

''' returns the version of the engine given full path to binary (e.g. Suricata, Snort) '''
def get_engine_version(path):
    version = 'unknown'
    try:
        process = subprocess.Popen("%s -V" % path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        regex = re.compile(r"(Version|Suricata version)\s+(?P<version>[\d\x2E]+)")
        if stderr:
            # apparently 'Snort -V' outputs to stderr....
            output = stderr
        else:
            output = stdout
        # get version from output
        result = regex.search(output)
        if result:
            version = result.group('version')
    except:
        pass
    return version

#*********************************
#*** Parse Comand Line Options ***
#*********************************
parser = OptionParser()
parser.add_option("-c", "--config",
                    dest="configfile",
                    help="path to config file [default: %default]",
                    default="dalton.conf")
(options, args) = parser.parse_args()

dalton_config_file = options.configfile

#**************************
#*** Constant Variables ***
#**************************

AGENT_VERSION = "2.0.0"
HTTP_HEADERS = {
    "User-Agent" : "Dalton Agent %s" % AGENT_VERSION
}

tcpdump_binary = '/usr/sbin/tcpdump'

# get options from dalton config file
config = ConfigParser.SafeConfigParser()

if not os.path.exists(dalton_config_file):
    print "Config file \'%s' does not exist.\n\nexiting." % dalton_config_file
    sys.exit(1)

try:
    config.read(dalton_config_file)
except Exception, e:
    print "Error reading config file, \'%s\'.\n\nexiting." % dalton_config_file
    sys.exit(1)

try:
    DEBUG = config.get('dalton', 'DEBUG')
    STORAGE_PATH = config.get('dalton', 'STORAGE_PATH')
    SENSOR_TECHNOLOGY = config.get('dalton', 'SENSOR_TECHNOLOGY').lower()
    SENSOR_UID = config.get('dalton', 'SENSOR_UID')
    DALTON_API = config.get('dalton', 'DALTON_API')
    API_KEY = config.get('dalton', 'API_KEY')
    POLL_INTERVAL = int(config.get('dalton', 'POLL_INTERVAL'))
    U2_ANALYZER_BINARY = config.get('dalton', 'U2_ANALYZER_BINARY')
    KEEP_JOB_FILES = config.get('dalton', 'KEEP_JOB_FILES')
except Exception, e:
    print "Error parsing config file, \'%s\':\n\n%s\n\nexiting." % (dalton_config_file, e)
    sys.exit(1)

if SENSOR_UID == 'auto':
    SENSOR_UID = socket.gethostname()

TCPDUMP_BINARY = 'auto'
try:
    TCPDUMP_BINARY = config.get('dalton', 'TCPDUMP_BINARY')
except Exception, e:
    pass
if TCPDUMP_BINARY == 'auto':
    TCPDUMP_BINARY = find_file('tcpdump')
if not TCPDUMP_BINARY or not os.path.exists(TCPDUMP_BINARY):
        print "Could not find 'tcpdump' binary."
        TCPDUMP_BINARY = ''

IDS_BINARY = 'auto'
try:
    IDS_BINARY = config.get('dalton', 'IDS_BINARY')
except Exception, e:
    pass
if IDS_BINARY == 'auto':
    IDS_BINARY = find_file('suricata')
if not IDS_BINARY or not os.path.exists(IDS_BINARY):
        print "Could not find 'suricata' binary, going to look for Snort."
        IDS_BINARY = None
if IDS_BINARY is None:
    # look for Snort
    IDS_BINARY = find_file('snort')
    if not IDS_BINARY or not os.path.exists(IDS_BINARY):
        print "Could not find 'snort' binary."
        print "ERROR: No IDS binary specified or found.  Cannot continue."
        sys.exit(1)

if SENSOR_TECHNOLOGY == 'auto':
    base = os.path.basename(IDS_BINARY)
    version = get_engine_version(IDS_BINARY)
    SENSOR_TECHNOLOGY = "%s-%s" % (base, version)

print "\n*******************"
print "Starting Dalton Agent:"
print "\tSENSOR_UID: %s" % SENSOR_UID
print "\tSENSOR_TECHNOLOGY: %s" % SENSOR_TECHNOLOGY
print "\tIDS_BINARY: %s" % IDS_BINARY
print "\tTCPDUMP_BINARY: %s" % TCPDUMP_BINARY

#************************
#*** Global Variables ***
#************************
JOB_ID = None
PCAP_FILES = []
IDS_RULES_FILES = None
IDS_CONFIG_FILE = None
VARIABLES_FILE = None
ENGINE_CONF_FILE = None
JOB_DIRECTORY = None
# dalton's log directory
JOB_LOG_DIRECTORY = None
# dalton's logs
JOB_ERROR_LOG = None
JOB_IDS_LOG = None
JOB_DEBUG_LOG = None
JOB_ALERT_LOG = None
JOB_ALERT_DETAILED_LOG = None
JOB_OTHER_LOGS = None
JOB_PERFORMANCE_LOG = None
# end dalton's logs
# used by snort for logs/alerts
# Suricata puts every log in here
IDS_LOG_DIRECTORY = None
TOTAL_PROCESSING_TIME = ''
# seconds
ERROR_SLEEP_TIME = 5

#**************************
#*** Custom Error Class ***
#**************************
class DaltonError(Exception):
    pass

#****************************************
#*** Communication/Printing Functions ***
#****************************************
def send_update(msg, job_id = None):
    global DALTON_API
    global SENSOR_UID
    global HTTP_HEADERS
    global API_KEY

    url = "%s/update/?apikey=%s" % (DALTON_API, API_KEY)

    params = {}
    params['uid'] = SENSOR_UID
    params['msg'] = msg
    params['job'] = job_id

    req = urllib2.Request(url, urllib.urlencode(params), HTTP_HEADERS)
    try:
        urllib2.urlopen(req)
    except Exception, e:
        try:
            truncated_url = re.search('(^[^\?]*)', url).group(1)
        except:
            truncated_url = "unknown"
        raise Exception("Error in sensor \'%s\' while processing job %s.  Could not communicate with controller in send_update().\nAttempted URL:\n%s" % (SENSOR_UID, job_id, truncated_url))

def request_job():
    global SENSOR_TECHNOLOGY, DALTON_API, SENSOR_UID, API_KEY, AGENT_VERSION

    url = "%s/request_job/%s/?SENSOR_UID=%s&AGENT_VERSION=%s&apikey=%s" % (DALTON_API, SENSOR_TECHNOLOGY, SENSOR_UID, AGENT_VERSION, API_KEY)

    try:
        data = urllib2.urlopen(url).read()
    except Exception, e:
        try:
            truncated_url = re.search('(^[^\?]*)', url).group(1)
        except:
            truncated_url = "unknown"
        raise Exception("Error in sensor \'%s\'.  Could not communicate with controller in request_job().\nAttempted URL:\n%s" % (SENSOR_UID, truncated_url))

    if (data == 'sleep'):
        #sleep
        return None
    else:
        #we got a job?
        try:
            job = json.loads(data)
        except Exception as e:
            print_error("Problem loading json from Dalton Controller; could not parse job id from data: '%s'." % data)
        return job

def request_zip(jid):
    global DALTON_API
    global SENSOR_UID
    global HTTP_HEADERS
    global STORAGE_PATH
    global API_KEY

    url = "%s/get_job/%s?apikey=%s" % (DALTON_API, jid, API_KEY)

    params = {}

    req = urllib2.Request(url, None, HTTP_HEADERS)
    try:
        zf = urllib2.urlopen(req)
    except Exception, e:
        try:
            truncated_url = re.search('(^[^\?]*)', url).group(1)
        except:
            truncated_url = "unknown"
        raise Exception("Error in sensor \'%s\' while requesting job %s.  Could not communicate with controller in request_zip().\nAttempted URL:\n%s" % (SENSOR_UID, jid, truncated_url))

    zf_path = "%s/%s.zip" % (STORAGE_PATH, jid)

    f = open(zf_path,'w')
    f.write(zf.read())
    f.close()
    return zf_path

# takes a re match object (should be a single byte) and returns it
# as printable.  Example: byte 0x13 becomes string "\x13".
def hexescape(matchobj):
    # apparently str.format wasn't added until python 2.6 so in case this is something like 2.4....
    #return r'\x{0:02x}'.format(ord(matchobj.group()))
    return r'\x%02x' % ord(matchobj.group())

# send results back to server.  Returns value of 'status' in results dictionary
def send_results():
    global DALTON_API, SENSOR_UID, HTTP_HEADERS, API_KEY
    global JOB_ID, JOB_DIRECTORY, JOB_ERROR_LOG, JOB_IDS_LOG, JOB_DEBUG_LOG, JOB_ALERT_LOG, JOB_ALERT_DETAILED_LOG, JOB_PERFORMANCE_LOG, TOTAL_PROCESSING_TIME, JOB_OTHER_LOGS

    print_debug("send_results() called")
    print_msg("Sending back results")

    nonprintable_re = re.compile(r'[\x80-\xFF]')

    # create and populate results dictionary
    results_dict = {}

    # populate error and status
    fh = open(JOB_ERROR_LOG, 'rb')
    results = fh.read()
    results_dict['error'] = results
    # if JOB_ERROR_LOG contains data
    if results:
        results_dict['status'] = "ERROR"
    else:
        results_dict['status'] = "SUCCESS"
    fh.close()

    # populate ids log
    results = ''
    fh = open(JOB_IDS_LOG, 'rb')
    results = fh.read()
    # make sure we have only ASCII
    results_dict['ids'] = ""
    for line in results:
        results_dict['ids'] += nonprintable_re.sub(hexescape, line)
    fh.close()

    # populate alert
    fh = open(JOB_ALERT_LOG, 'rb')
    results = fh.read()
    if not results:
        results_dict['alert'] = "*** No Alerts ***\n"
    else:
        results_dict['alert'] = results
    fh.close()

    # populate alert detailed
    fh = open(JOB_ALERT_DETAILED_LOG, 'rb')
    results = fh.read()
    fh.close()
    if not results: # or error identified in results?
        results_dict['alert_detailed'] = ""
    else:
        # sometimes u2spewfoo will output non-utf8 data. This happens in
        # ExtraData records, usually when the sensor incorrectly parses/identifies
        # HTTP traffic.  Attempt to convert.
        results_dict['alert_detailed'] = ""
        for line in results:
            results_dict['alert_detailed'] += nonprintable_re.sub(hexescape, line)

    # populate performance
    fh = open(JOB_PERFORMANCE_LOG, 'rb')
    results = fh.read()
    results_dict['performance'] = results
    fh.close()

    # populate debug
    fh = open(JOB_DEBUG_LOG, 'rb')
    results = fh.read()
    results_dict['debug'] = results
    fh.close()

    # populate TOTAL_PROCESSING_TIME
    results_dict['total_time'] = TOTAL_PROCESSING_TIME

    # populate other logs (Suricata only for now)
    # this file actually contains json; Dalton controller will have to (double) decode since
    # results_dict is json encoded before it is sent
    fh = open(JOB_OTHER_LOGS, 'rb')
    results = fh.read()
    results_dict['other_logs'] = results
    fh.close()

    # convert the dictionary to json
    json_results_dict = json.dumps(results_dict)
    #if DEBUG:
    #    fh = open('/tmp/dictionary.txt', 'wb')
    #    fh.write(json_results_dict)
    #    fh.close()

    payload = {'json_data': json_results_dict}
    # send results back to server
    post_results(payload)
    return results_dict['status']

def post_results(json_data):
    global DALTON_API, SENSOR_UID, HTTP_HEADERS, API_KEY
    url = "%s/results/%s?SENSOR_UID=%s&apikey=%s" % (DALTON_API, JOB_ID, SENSOR_UID, API_KEY)
    req = urllib2.Request(url, urllib.urlencode(json_data), HTTP_HEADERS)
    try:
        response = urllib2.urlopen(req)
    except Exception, e:
        try:
            truncated_url = re.search('(^[^\?]*)', url).group(1)
        except:
            truncated_url = "unknown"
        raise Exception("Error in sensor \'%s\' while processing job %s.  Could not communicate with controller in post_results().\nAttempted URL:\n%s\nError:\n%s" % (SENSOR_UID, JOB_ID, truncated_url, e))

def error_post_results(error_msg):
    global SENSOR_UID
    results_dict = {}
    results_dict['error'] = "Unexpected error on Dalton Agent \'%s\', please try your job again or contact admin with this message (see \'About\' page for contact info).  Error message:\n\n%s" % (SENSOR_UID, error_msg)
    results_dict['status'] = "ERROR"
    results_dict['ids'] = ''
    results_dict['alert'] = "*** No Alerts ***\n"
    results_dict['performance'] = ''
    results_dict['debug'] = ''
    results_dict['total_time'] = ''

    json_results_dict = json.dumps(results_dict)
    payload = {'json_data': json_results_dict}
    post_results(payload)

def print_error(msg):
    global JOB_ERROR_LOG, SENSOR_TECHNOLOGY
    if JOB_ERROR_LOG:
        fh = open(JOB_ERROR_LOG, "a")
        fh.write("%s\n" % msg)
        fh.close()
    else:
        if DEBUG:
            print "print_error() called but no JOB_ERROR_LOG exists"
    print_msg("ERROR!")
    print_debug("ERROR:\n%s" % msg)
    # throw error
    raise DaltonError(msg)

def print_msg(msg):
    print_debug(msg)
    # send message
    if DEBUG:
        print msg
    send_update(msg, JOB_ID)

def print_debug(msg):
    global JOB_DEBUG_LOG
    if JOB_DEBUG_LOG:
        fh = open(JOB_DEBUG_LOG, "a")
        fh.write("*****\n%s\n" % msg)
        fh.close()
    else:
        if DEBUG:
            print "print_debug() called but no JOB_DEBUG_LOG exists"


# process alert output from Snort
def process_snort_alerts():
    global IDS_LOG_DIRECTORY, JOB_ALERT_LOG, JOB_ALERT_DETAILED_LOG, SENSOR_TECHNOLOGY
    print_debug("process_snort_alerts() called")
    print_msg("Processing alerts")
    os.system("sudo chmod -R 755 %s" % IDS_LOG_DIRECTORY)

    job_alert_log_fh = open(JOB_ALERT_LOG, "wb")
    for alert_file in glob.glob(os.path.join(IDS_LOG_DIRECTORY, "alert*")):
        alert_filehandle = open(alert_file, "rb")
        print_debug("Processing snort alert file %s" % alert_file)
        job_alert_log_fh.write(alert_filehandle.read())
        alert_filehandle.close()
    job_alert_log_fh.close()

def check_pcaps():
    """ 
    Check of the pcaps and alert on potential issues.
    Add other checks here as needed.
    """
    global PCAP_FILES, tcpdump_binary, JOB_ALERT_LOG, SENSOR_TECHNOLOGY, JOB_ERROR_LOG
    print_debug("check_pcaps() called")

    # Check of the pcaps to make sure none were submitted with TCP packets but no TCP packets have the SYN flag
    # only call if no alerts fired
    if os.path.getsize(JOB_ALERT_LOG) == 0:
        try:
            if os.path.exists(tcpdump_binary):
                for pcap in PCAP_FILES:
                    # check for TCP packets
                    if len(subprocess.Popen("%s -nn -q -c 1 -r %s -p tcp 2>/dev/null" % (tcpdump_binary, pcap), shell=True, stdout=subprocess.PIPE).stdout.read()) > 0:
                        # check for SYN packets
                        if len(subprocess.Popen("%s -nn -q -c 1 -r %s \"tcp[tcpflags] & tcp-syn != 0\" 2>/dev/null" % (tcpdump_binary, pcap), shell=True, stdout=subprocess.PIPE).stdout.read()) == 0:
                            print_error("As Dalton says, \"pain don\'t hurt.\" But an incomplete pcap sure can."
                                        "\n\n"
                                        "The pcap file \'%s\' contains TCP traffic but does not "
                                        "contain any TCP packets with the SYN flag set."
                                        "\n\n"
                                        "Almost all IDS rules that look for TCP traffic require "
                                        "an established connection.\nYou will need to provide a more complete "
                                        "pcap if you want accurate results." 
                                        "\n\n"
                                        "If you need help crafting a pcap, FlowSynth may be able to help --\n"
                                        "http://flowsynth/pcap/build - (TODO: link needed)" 
                                        "\n\n"
                                        "And, \"there's always barber college....\"" % os.path.basename(pcap))
            else:
                print_debug("In check_pcaps() -- no tcpdump binary found at %s" % tcpdump_binary)
        except Exception, e:
            if not str(e).startswith("As Dalton says"):
                print_debug("Error doing TCP SYN check in check_pcaps():\n%s" % e)

    # check snaplen of pcaps
    try:
        for pcap in PCAP_FILES:
            snaplen_offset = 16
            pcapng = False
            little_endian = False
            snaplen = 65535

            # get first 40 bytes of pcap file
            fh = open(pcap, 'rb')
            bytes = fh.read(44)
            fh.close()

            magic = ''.join(b.encode('hex') for b in bytes[0:4])
            if magic.lower() == '0a0d0d0a':
                # this is pcapng and these aren't the byte-order magic bytes
                snaplen_offset = 40
                pcapng = True
                # get the correct byte-order magic bytes for pcapng
                magic = ''.join(b.encode('hex') for b in bytes[8:12])
            else:
                # this is libpcap, we have the magic
                pcapng = False
            # now determine endian-ness
            if magic.lower() == 'a1b2c3d4':
                # this is "big endian"
                little_endian = False
            elif magic.lower() == '4d3c2b1a' or magic.lower() == 'd4c3b2a1':
                # this is little endian
                little_endian = True
            else:
                print_debug("in check_pcaps() - Pcap Byte-Order Magic field not found in file \'%s\'.  Is this a valid pcap?" % os.path.basename(pcap))
                continue

            # get snaplen
            if little_endian:
                snaplen = struct.unpack('<i', bytes[snaplen_offset:snaplen_offset+4])[0]
            else:
                snaplen = struct.unpack('>i', bytes[snaplen_offset:snaplen_offset+4])[0]

            # Python 2.4 doesn't support this so doing it the ugly way
            #print_debug("Packet capture file \'%s\' is format %s, %s, and has snaplen of %d bytes." % (os.path.basename(pcap), ('pcapng' if pcapng else 'libpcap'), ('little endian' if little_endian else 'big endian'), snaplen))
            debug_msg = "Packet capture file \'%s\' is format " % os.path.basename(pcap)
            if pcapng:
                debug_msg += "pcapng, "
            else:
                debug_msg += "libpcap, "
            if little_endian:
                debug_msg += "little endian, and has snaplen of %d bytes." % snaplen
            else:
                debug_msg += "big endian, and has snaplen of %d bytes." % snaplen
            print_debug(debug_msg)

            if snaplen < 65535:
                print_debug("Warning: \'%s\' was captured using a snaplen of %d bytes.  This may mean you have truncated packets." % (os.path.basename(pcap), snaplen))

            # validate snaplen
            if snaplen < 1514:
                warning_msg = ''
                if not os.path.getsize(JOB_ERROR_LOG) == 0:
                    warning_msg += "\n----------------\n\n"
                warning_msg += "Warning: \'%s\' was captured using a snaplen of %d bytes.  This may mean you have truncated packets." % (os.path.basename(pcap), snaplen)
                if snaplen == 1500:
                    warning_msg += "\n\nSome sandboxes (Bluecoat/Norman) will put a hardcoded snaplen of 1500 bytes\n"
                    warning_msg += "on pcaps even when the packets are larger than 1500 bytes.  This can result in the sensor throwning away these\n"
                    warning_msg += "packets and not inspecting them.  If this is the case, try saving the file in Wireshark in pcapng format, opening up\n"
                    warning_msg += "that pcapng file in Wireshark, and saving it as a libpcap file. This should set the snaplen to 65535."
                warning_msg += "\n\nThis is just a warning message about the pcap. The job ran successfully and the generated alerts as well as other\n"
                warning_msg += "results have been returned."
                print_error(warning_msg)
    except Exception, e:
        if not str(e).startswith("Warning:"):
            print_debug("Error doing snaplen check in check_pcaps():\n%s" % e)

#*************************
#**** Snort Functions ****
#*************************
def run_snort():
    global IDS_BINARY, IDS_RULES_FILES, IDS_CONFIG_FILE, IDS_LOG_DIRECTORY, JOB_IDS_LOG, PCAP_FILES, SENSOR_TECHNOLOGY
    print_debug("run_snort() called")
    # note: if we don't have '--treat-drop-as-alert' then some alerts in a stream that has already triggered a 'drop' rule won't fire since they are assumed to already blocked by the DAQ
    snort_command = "%s -Q --daq dump --daq-dir /usr/lib/daq/ --daq-var load-mode=read-file --daq-var file=/tmp/inline-out.pcap -l %s -c %s -k none -X --conf-error-out --process-all-events --treat-drop-as-alert --pcap-list=\"%s\" 2>&1" % (IDS_BINARY, IDS_LOG_DIRECTORY, IDS_CONFIG_FILE, ' '.join(PCAP_FILES))
    print_msg("Starting Snort and Running Pcap(s)...")
    print_debug("Running Snort with the following command command:\n%s" % snort_command)
    snort_output_fh = open(JOB_IDS_LOG, "wb")
    subprocess.call(snort_command, shell =  True, stderr=subprocess.STDOUT, stdout=snort_output_fh)
    snort_output_fh.close()

#************************
#** Suricata Functions **
#************************

def run_suricata():
    global IDS_BINARY, IDS_CONFIG_FILE, IDS_LOG_DIRECTORY, JOB_ALERT_LOG, PCAP_FILES, JOB_IDS_LOG
    print_debug("run_suricata() called")
    if not IDS_BINARY:
        print_error("No Suricata binary found on system.")
    print_msg("Running pcap(s) thru Suricata")
    suricata_command = "%s -c %s -l %s -k none -r %s" % (IDS_BINARY, IDS_CONFIG_FILE, IDS_LOG_DIRECTORY, PCAP_FILES[0])
    print_debug("Running suricata with the following command:\n%s" % suricata_command)
    suri_output_fh = open(JOB_IDS_LOG, "wb")
    subprocess.call(suricata_command, shell = True, stderr=subprocess.STDOUT, stdout=suri_output_fh)
    suri_output_fh.close()

# generate fast pattern info; this requires a separate Suricata run
#   with the '--engine-analysis' flag set
def generate_fast_pattern():
    global IDS_BINARY, IDS_CONFIG_FILE, IDS_LOG_DIRECTORY, SENSOR_TECHNOLOGY
    print_debug("generate_fast_pattern() called")
    print_msg("Generating Fast Pattern Info")
    if SENSOR_TECHNOLOGY.startswith('suri'):
        if not IDS_BINARY:
            print_error("No Suricata binary found on system.")
        suricata_command = "%s -c %s -l %s --engine-analysis" % (IDS_BINARY, IDS_CONFIG_FILE, IDS_LOG_DIRECTORY)
        print_debug("Running suricata with the following command to get fast pattern info:\n%s" % suricata_command)
        # send output to /dev/null for now
        suri_output_fh = open(os.devnull, "wb")
        subprocess.call(suricata_command, shell = True, stderr=subprocess.STDOUT, stdout=suri_output_fh)
        suri_output_fh.close()

def process_suri_alerts():
    global JOB_ALERT_LOG, IDS_LOG_DIRECTORY
    print_debug("process_suri_alerts() called")
    print_msg("Processing alerts")
    alerts_file = "%s/fast.log" % IDS_LOG_DIRECTORY
    if os.path.exists(alerts_file):
        job_alert_log_fh = open(JOB_ALERT_LOG, "wb")
        alert_filehandle = open(alerts_file, "rb")
        for line in alert_filehandle:
            # can do alert formatting here if we want
            # for now just add newline between alerts
            job_alert_log_fh.write("%s\n" % line)
        alert_filehandle.close()
        job_alert_log_fh.close()
    else:
        print_debug("No alerts found. File \'%s\' does not exist." % alerts_file)

def process_other_logs(other_logs):
    """ 
    Takes a dictionary of Display Name, filename pairs for logs in the IDS_LOG_DIRECTORY and poulates
    the JOB_OTHER_LOGS with a dictonary containing the Display Name and file contents.
    """
    global JOB_OTHER_LOGS, IDS_LOG_DIRECTORY, SENSOR_TECHNOLOGY
    print_debug("process_other_logs() called")
    print_msg("Processing other logs")
    if len(other_logs) > 0:
        all_other_logs = {}
        for log_name in other_logs:
            if os.path.exists("%s/%s" % (IDS_LOG_DIRECTORY, other_logs[log_name])):
                log_fh = open("%s/%s" % (IDS_LOG_DIRECTORY, other_logs[log_name]), "rb")
                all_other_logs[log_name] = log_fh.read()
                log_fh.close()
                if all_other_logs[log_name] == "":
                    print_debug("log \"%s\" is empty, not inclding" % log_name)
                    del all_other_logs[log_name]
            else:
                print_debug("Requested log file \'%s\' not present, skipping." % other_logs[log_name])
        other_logs_fh = open(JOB_OTHER_LOGS, "wb")
        other_logs_fh.write(json.dumps(all_other_logs))
        other_logs_fh.close()
    else:
        print_debug("No additional logs requested.")

def check_for_errors(tech):
    """ checks the IDS output for error messages """
    global JOB_ERROR_LOG, JOB_IDS_LOG
    print_debug("check_for_errors() called")
    if not tech:
        tech = 'suricata'
        print_debug("\'tech\' variable not passed to check_for_errors(), using \'%s\'" % tech)
    error_lines = []
    try:
        ids_log_fh = open(JOB_IDS_LOG, "rb")
        for line in ids_log_fh:
            if tech.startswith('suri'):
                if (" - <Error> - " in line or line.startswith("ERROR") or line.startswith("Failed to parse configuration file")):
                    error_lines.append(line)
                    if "bad dump file format" in line:
                        error_lines.append("Bad pcap file(s) submitted to Suricata. Pcap files should be in libpcap format (pcapng is not supported in older Suricata versions).\n")
            elif tech.startswith('snort'):
                if "ERROR:" in line or "FATAL" in line or "Fatal Error" in line or "Segmentation fault" in line or line.startswith("Error "):
                    error_lines.append(line)
                    if "unknown file format" in line:
                        error_lines.append("Bad pcap file(s) submitted to Snort. Pcap files should be in libpcap or pcapng format.\n")
        ids_log_fh.close()
    except Exception, e:
        print_error("Error reading IDS output file \'%s\'. Error:\n\n%s" % (JOB_IDS_LOG, e))

    if len(error_lines) > 0:
        print_error("Error message(s) found in IDS output. See \"IDS Engine\" tab for more details and/or context:\n\n%s" % '\n'.join(error_lines))

# process unified2 data and populate JOB_ALERT_DETAILED_LOG (only for sensors that generate unified2 logs such as Snort and Suricata)
def process_unified2_logs():
    global IDS_LOG_DIRECTORY, JOB_ALERT_LOG, JOB_ALERT_DETAILED_LOG, SENSOR_TECHNOLOGY, U2_ANALYZER_BINARY
    print_debug("process_unified2_logs() called")
    print_msg("Processing unified2 logs")
    u2_binary_exists = True
    # check to make sure U2_ANALYZER_BINARY exists (note that the U2_ANALYZER_BINARY variable is set in the conf file)
    for myitem in U2_ANALYZER_BINARY.split(' '):
        #print_debug("checking %s" % myitem)
        if not os.path.exists(myitem):
            print_debug("Error: the file \'%s\' referenced in U2_ANALYZER_BINARY (\'%s\') does not exist on this sensor, not processing unified2 logs." % (myitem, U2_ANALYZER_BINARY))
            #print_error("Error processing unified2 files.  Files needed to perform analysis not found.  This sensor may not support detailed alert data yet.  See debug log for details.")
            u2_binary_exists = False

    if u2_binary_exists:
        # see if unified2 logs exist and process them; add to JOB_ALERT_DETAILED_LOG
        print_debug("Identifying unified2 log files...")
        job_alert_detailed_log_fh = open(JOB_ALERT_DETAILED_LOG, "wb")
        # in some cases the unified2.alert filenames are prepended with a period but
        #  this isn't normal behavior; it should be file, 'unified2.alert.<timestamp>'.
        #  glob treats files with leading period differently (won't match '*')
        #  glob thru ".unified2.alert*" and "unified2.alert*", put in a list, and then iterate thru that
        unified2_files = []
        for u2_file in glob.glob(os.path.join(IDS_LOG_DIRECTORY, ".unified2.alert*")):
            print_debug("Adding unified2 alert file to processing list: %s" % u2_file)
            unified2_files.append(u2_file)
        for u2_file in glob.glob(os.path.join(IDS_LOG_DIRECTORY, "unified2.alert*")):
            print_debug("Adding unified2 alert file to processing list: %s" % u2_file)
            unified2_files.append(u2_file)
        # below print line use for testing; comment it out when not debugging
        # print "unified2_files for processing: %s" % unified2_files
        if len(unified2_files) <= 0:
            print_debug("No unified2 files found.")
        for unified2_file in unified2_files:
            # call to u2spewfoo.py here, populate JOB_ALERT_DETAILED_LOG
            # filename validation to prevent OS command injection; will need to update if future sensor versions use different file names
            if not re.match('\.?unified2\.alert\.?\d*', os.path.basename(unified2_file)):
                print_debug("Invalid unified2 filename found, not processing: %s" % unified2_file)
            else:
                # call to process unified2 alerts
                u2processing_command = "%s %s" % (U2_ANALYZER_BINARY, unified2_file)
                print_debug("Processing unified2 file, %s\n\tunified2 file processing command:\n\t%s" % (unified2_file, u2processing_command))
                #below two lines used for debugging, not for use in prod
                #u2spewfoo_response = subprocess.Popen(u2processing_command, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.read()
                #print "RESPONSE: %s" % u2spewfoo_response
                subprocess.call(u2processing_command, shell=True, stderr=subprocess.STDOUT, stdout=job_alert_detailed_log_fh)
                #maybe add a newline to job_alert_detailed_log_fh here??
        job_alert_detailed_log_fh.close()

# process performance output (Snort and Suricata)
def process_performance_logs():
    global IDS_LOG_DIRECTORY, JOB_PERFORMANCE_LOG, SENSOR_TECHNOLOGY
    print_debug("process_performance_logs() called")
    print_msg("Processing performance logs")
    os.system("sudo chmod -R 755 %s" % IDS_LOG_DIRECTORY)
    job_performance_log_fh = open(JOB_PERFORMANCE_LOG, "wb")
    if SENSOR_TECHNOLOGY.startswith('is'):
        if len(glob.glob(os.path.join(IDS_LOG_DIRECTORY, "rules_stats*"))) > 0:
            for perf_file in glob.glob(os.path.join(IDS_LOG_DIRECTORY, "rules_stats*")):
                perf_filehandle = open(perf_file, "rb")
                print_debug("Processing snort performance file %s" % perf_file)
                job_performance_log_fh.write(perf_filehandle.read())
                job_performance_log_fh.write("\n")
                perf_filehandle.close()
        else:
            print_debug("No Snort performance log(s) found.")
    elif SENSOR_TECHNOLOGY.startswith('suri'):
        perf_file = "%s/rule-perf.log" % IDS_LOG_DIRECTORY
        if os.path.exists(perf_file):
            perf_filehandle = open(perf_file, "rb")
            print_debug("Processing Suricata performance file %s" % perf_file)
            job_performance_log_fh.write(perf_filehandle.read())
            perf_filehandle.close()
        else:
            print_debug("No performance log found. File \'%s\' does not exist." % perf_file)
    job_performance_log_fh.close()

#****************************
#*** Submit Job Functions ***
#****************************
# resets the global variables between jobs
def reset_globals():
    global JOB_ID, PCAP_FILES, IDS_RULES_FILES, IDS_CONFIG_FILE, ENGINE_CONF_FILE, VARIABLES_FILE, JOB_DIRECTORY, JOB_LOG_DIRECTORY, JOB_ERROR_LOG, JOB_IDS_LOG, JOB_DEBUG_LOG, JOB_ALERT_LOG, JOB_ALERT_DETAILED_LOG, JOB_PERFORMANCE_LOG, IDS_LOG_DIRECTORY, TOTAL_PROCESSING_TIME, JOB_OTHER_LOGS

    JOB_ID = None
    PCAP_FILES = []
    IDS_RULES_FILES = []
    IDS_CONFIG_FILE = None
    VARIABLES_FILE = None
    ENGINE_CONF_FILE = None
    JOB_DIRECTORY = None
    # dalton's log directory
    JOB_LOG_DIRECTORY = None
    # dalton's logs
    JOB_ERROR_LOG = None
    JOB_IDS_LOG = None
    JOB_DEBUG_LOG = None
    JOB_ALERT_LOG = None
    JOB_ALERT_DETAILED_LOG = None
    JOB_OTHER_LOGS = None
    JOB_PERFORMANCE_LOG = None
    # end dalton's logs
    # used by snort for logs/alerts
    IDS_LOG_DIRECTORY = None
    TOTAL_PROCESSING_TIME = ''
    JOB_OTHER_LOGS = None

# main function
# gets passed directory of submitted files (rules file, pcap file(s), variables file) and job ID
def submit_job(job_id, job_directory):
    global JOB_ID, SENSOR_TECHNOLOGY, PCAP_FILES, IDS_RULES_FILES, IDS_CONFIG_FILE, ENGINE_CONF_FILE, VARIABLES_FILE, JOB_DIRECTORY, JOB_LOG_DIRECTORY, JOB_ERROR_LOG, JOB_IDS_LOG, JOB_DEBUG_LOG, JOB_ALERT_LOG, JOB_ALERT_DETAILED_LOG, JOB_OTHER_LOGS, JOB_PERFORMANCE_LOG, IDS_LOG_DIRECTORY, TOTAL_PROCESSING_TIME, IDS_BINARY
    # reset and populate global vars
    reset_globals()
    (JOB_ID, JOB_DIRECTORY) = (job_id, job_directory)
    JOB_DIRECTORY = JOB_DIRECTORY.rstrip('/')
    JOB_LOG_DIRECTORY = '%s/output_logs' % JOB_DIRECTORY
    if os.path.isdir(JOB_LOG_DIRECTORY):
        shutil.rmtree(JOB_LOG_DIRECTORY)
    os.makedirs(JOB_LOG_DIRECTORY)
    JOB_ERROR_LOG = '%s/error.log' % JOB_LOG_DIRECTORY
    JOB_IDS_LOG = '%s/ids.log' % JOB_LOG_DIRECTORY
    JOB_DEBUG_LOG = '%s/debug.log' % JOB_LOG_DIRECTORY
    JOB_ALERT_LOG = '%s/alerts.log' % JOB_LOG_DIRECTORY
    JOB_ALERT_DETAILED_LOG = '%s/alerts_detailed.log' % JOB_LOG_DIRECTORY
    JOB_OTHER_LOGS = '%s/other_logs.json' % JOB_LOG_DIRECTORY
    JOB_PERFORMANCE_LOG = '%s/performance.log' % JOB_LOG_DIRECTORY
    IDS_CONFIG_FILE = '%s/snort.conf' % JOB_DIRECTORY

    # touch log files
    open(JOB_ERROR_LOG, "wb").close()
    open(JOB_IDS_LOG, "wb").close()
    open(JOB_DEBUG_LOG, "wb").close()
    open(JOB_ALERT_LOG, "wb").close()
    open(JOB_ALERT_DETAILED_LOG, "wb").close()
    open(JOB_OTHER_LOGS, "wb").close()
    open(JOB_PERFORMANCE_LOG, "wb").close()

    print_debug(datetime.datetime.now().strftime("%b %d %Y %H:%M:%S"))
    print_debug("Agent Name: %s\nAgent Version: %s\nSensor Type: %s\nDalton API: %s" % (SENSOR_UID, AGENT_VERSION, SENSOR_TECHNOLOGY, DALTON_API))

    print_debug("submit_job() called")

    # read manifest file
    manifest_data = []
    if os.path.exists("%s/manifest.json" % JOB_DIRECTORY):
        manifest_file = open("%s/manifest.json" % JOB_DIRECTORY, "rb")
        for line in manifest_file:
            manifest_data.append(json.loads(line))
        manifest_file.close()
    print_debug("manifest.json: %s" % manifest_data)

    trackPerformance = False
    try:
        trackPerformance = manifest_data[0]['track-performance']
    except Exception:
        trackPerformance = False

    # only submitted for Suricata jobs
    # fast pattern data for Snort can be generated by adding
    #   "debug-print-fast-pattern" to the end of the "config detection: " line
    #   in the submitted engine.conf
    getFastPattern = False
    try:
        getFastPattern = manifest_data[0]['get-fast-pattern']
    except Exception:
        getFastPattern = False

    # engine statistics, Snort only
    getEngineStats = False
    try:
        getEngineStats = manifest_data[0]['get-engine-stats']
    except Exception:
        getEngineStats = False

    # process unified2 alerts, supported for Snort and suricata
    getAlertDetailed = False
    try:
        getAlertDetailed = manifest_data[0]['alert-detailed']
    except Exception:
        getAlertDetailed = False

    # get other logs (Suricata only for now)
    getOtherLogs = False
    try:
        getOtherLogs = manifest_data[0]['get-other-logs']
    except Exception:
        getOtherLogs = False

    # make a directory for snort to use for alert and perf logs
    IDS_LOG_DIRECTORY = '%s/raw_ids_logs' % JOB_DIRECTORY
    if os.path.isdir(IDS_LOG_DIRECTORY):
        shutil.rmtree(IDS_LOG_DIRECTORY)
    os.makedirs(IDS_LOG_DIRECTORY)
    # not secure
    os.system("sudo chmod -R 777 %s" % IDS_LOG_DIRECTORY)

    # pcaps and config should be in manifest
    IDS_CONFIG_FILE = None
    try:
        IDS_CONFIG_FILE = os.path.join(JOB_DIRECTORY, os.path.basename(manifest_data[0]['engine-conf']))
    except Exception:
        print_error("Could not extract engine configuration file from job.")

    try:
        PCAP_FILES = [os.path.join(JOB_DIRECTORY, os.path.basename(cap)) for cap in manifest_data[0]['pcaps']]
    except Exception:
        print_error("Could not determine pcap files in job.")


    # parse job dir for configs and pcaps
    if DEBUG:
        print "Parsing job directory: %s" % JOB_DIRECTORY
    for file in glob.glob(os.path.join(JOB_DIRECTORY, "*")):
        if not os.path.isfile(file):
            continue
        if os.path.splitext(file)[1] == '.rules':
            IDS_RULES_FILES.append(file)
        elif os.path.basename(file) == 'variables.conf':
            VARIABLES_FILE = file

    # for now for testing in case the variables file isn't included in the .zip downloaded by the agent
    if not VARIABLES_FILE:
        #TODO: clean up
        pass
        #VARIABLES_FILE = '/opt/dalton/config/variables.conf'
        #print_debug("variables.conf not defined, using %s" % VARIABLES_FILE)

    # input validation (sort of)
    if not PCAP_FILES:
        print_error("No pcap files found")
    if not IDS_RULES_FILES:
        print_error("No rules files found")
    if not VARIABLES_FILE or not os.path.exists(VARIABLES_FILE):
        print_error("variables file %s does not exist" % VARIABLES_FILE)
    if not JOB_ID:
        print_error("job id not defined")

    if SENSOR_TECHNOLOGY.startswith('snort'):
#        # Create snort.conf from MASTER_CONFIG_FILE and update it to include
#        # the ENGINE_CONF_FILE (if it is submitted with the job) along with
#        # the VARIABLE_FILE and IDS_RULES_FILES
#        # this behavior has changed
#        if not os.path.exists(MASTER_CONFIG_FILE):
#            print_error("master config file %s does not exist" % MASTER_CONFIG_FILE)
#        regex = re.compile(r"^(?P<start>include\:?\s).*engine\.conf")
#        master_conf_fh = open(MASTER_CONFIG_FILE, "rb")
#        master_conf_file = master_conf_fh.readlines()
#        master_conf_fh.close()
        snort_conf_fh = open(IDS_CONFIG_FILE, "a")
#        replaced_engine_conf_line = False
#        for line in master_conf_file:
#            # if engine.conf included in job, use that
#            if ENGINE_CONF_FILE:
#                result = regex.search(line)
#                if result:
#                    snort_conf_fh.write("%s%s" % (result.group('start'), ENGINE_CONF_FILE))
#                    replaced_engine_conf_line = True
#                else:
#                    snort_conf_fh.write("%s" % line)
#            else:
#                snort_conf_fh.write("%s" % line)
#
#        if ENGINE_CONF_FILE and not replaced_engine_conf_line:
#            snort_conf_fh.write("\ninclude %s\n" % ENGINE_CONF_FILE)

        # include rules and vars files in config file
        for rules_file in IDS_RULES_FILES:
            snort_conf_fh.write("\ninclude %s\n" % rules_file)
        snort_conf_fh.write("\ninclude %s\n" % VARIABLES_FILE)
        snort_conf_fh.close()

    if SENSOR_TECHNOLOGY.startswith('suri'):
        # add variables and rules to Suricata's .yaml file
        suri_yaml_fh = open(IDS_CONFIG_FILE, "a")
        suri_yaml_fh.write("\n")
        # add variables
        suri_vars_fh = open(VARIABLES_FILE, "rb")
        suri_yaml_fh.write(suri_vars_fh.read())
        suri_yaml_fh.write("\n")
        suri_vars_fh.close()
        # add rules
        #TODO: this will redefine the default-rule-path and rules-file config nodes
        # is this desired? Do we only want rulesets from the controller or can
        # other rules files be included in the config? If the latter we will need
        # to parse the YAML and insert the rules includes appropriately.
        print_debug("adding rules files(s) to yaml:\n%s\n" % '\n'.join(IDS_RULES_FILES))
        suri_yaml_fh.write("default-rule-path: %s\n" % JOB_DIRECTORY)
        suri_yaml_fh.write("rule-files:\n")
        for rules_file in IDS_RULES_FILES:
            suri_yaml_fh.write(" - %s\n" % rules_file)
        suri_yaml_fh.close()
        if len(PCAP_FILES) > 1:
            print_error("Multiple pcap files were submitted to the Dalton Agent for a Suricata job.\n\nSuricata can only read a single pcap file so multiple pcaps submitted to the Dalton Controller should have been combined by the Controller when packaging the job.\n\nIf you see this, something went wrong on the Controller or you are doing something untoward.")
    if SENSOR_TECHNOLOGY.startswith('snort'):
        # this section applies only to Snort sensors
        # Snort uses DAQ dump and pcap read mode
        run_snort()

        # process snort alerts
        process_snort_alerts()

    elif SENSOR_TECHNOLOGY.startswith('suri'):
        # this section for Suricata agents
        if getFastPattern:
            generate_fast_pattern()
        # run the Suricata job
        run_suricata()
        # populate the alerts (fast.log)
        process_suri_alerts()

    # the rest of this can apply to Snort and Suricata

    # other logs to return from the job; sensor specific
    other_logs = {}
    if SENSOR_TECHNOLOGY.startswith('suri'):
        # always return Engine and Packet Stats for Suri
        other_logs['Engine Stats'] = 'stats.log'
        other_logs['Packet Stats'] = 'packet-stats.log'
        if getOtherLogs:
            other_logs['Alert Debug'] = 'alert-debug.log'
            other_logs['HTTP Log'] = 'http.log'
            other_logs['TLS Log'] = 'tls.log'
            other_logs['DNS Log'] = 'dns.log'
            other_logs['EVE JSON'] = 'eve.json'
        if getFastPattern:
            other_logs['Fast Pattern'] = 'rules_fast_pattern.txt'
        if trackPerformance:
            other_logs['Keyword Perf'] = 'keyword-perf.log'
    # elif ... can add processing of logs from other engines here
    if len(other_logs) > 0:
        process_other_logs(other_logs)

    # process unified2 data (if applicable)
    if getAlertDetailed:
        process_unified2_logs()
    else:
        print_debug("Not processing unified2 logs (either the sensor technology does not generate these or the option was not selected).")

    # process performance data
    if trackPerformance:
        process_performance_logs()
    else:
        print_debug("Performance tracking disabled, not processing performance logs")

    # check IDS output for error messages not identified and/or
    # handled elsewhere. Applies to Suri and Snort for now
    # calling this last so that everything else is populated
    # and can be sent back even though there could be an error
    check_for_errors(SENSOR_TECHNOLOGY)

    # check the pcaps to make sure incomplete, truncated, etc. pcaps weren't submitted.
    check_pcaps()

#################################################
# agent part: send files via json, clean up files
while True:
    try:
        job = request_job()
        if (job != None):
            start_time = int(time.time())
            JOB_ID = job['id']
            if DEBUG:
                print datetime.datetime.now().strftime("%b %d %Y %H:%M:%S")
                print "Job %s Accepted by %s" % (JOB_ID, SENSOR_UID)
            send_update("Job %s Accepted by %s" % (JOB_ID, SENSOR_UID), JOB_ID)
            zf_path = request_zip(JOB_ID)
            if DEBUG:
                print "Downloaded zip for %s successfully. Extracting file %s" % (JOB_ID, zf_path)
            send_update("Downloaded zip for %s successfully; extracting..." % JOB_ID, JOB_ID)
            # JOB_DEBUG_LOG not defined yet so can't call print_debug() here
            #print_debug("Extracting zip file for job id %s" % JOB_ID)
            JOB_DIRECTORY = "%s/%s_%s" % (STORAGE_PATH, JOB_ID, datetime.datetime.now().strftime("%b-%d-%Y_%H-%M-%S"))
            os.makedirs(JOB_DIRECTORY)
            zf = zipfile.ZipFile(zf_path, 'r')
            filenames = zf.namelist()
            for filename in filenames:
                if DEBUG:
                    print "extracting file, %s" % filename
                fh = open("%s/%s" % (JOB_DIRECTORY, filename), "wb")
                fh.write(zf.read(filename))
                fh.close()
            zf.close()
            if DEBUG:
                print "Done extracting zipped files."

            # submit the job!
            try:
                submit_job(JOB_ID, JOB_DIRECTORY)
            except DaltonError, e:
                # dalton errors should already be written to JOB_ERROR_LOG and sent back
                if DEBUG:
                    print "DaltonError caught:\n%s" % e
            except Exception, e:
                # not a DaltonError, perhaps a code bug? Try to write to JOB_ERROR_LOG
                if JOB_ERROR_LOG:
                    msg = "Dalton Agent error in sensor \'%s\' while processing job %s. Exception in submit_job().  Please re-submit or contact admin with this message (see \'About\' page for contact info).  Error message:\n\n%s" % (SENSOR_UID, JOB_ID, e)
                    fh = open(JOB_ERROR_LOG, "a")
                    fh.write("%s\n" % msg)
                    fh.close()
                    print_msg("ERROR!")
                    print_debug("ERROR:\n%s" % msg)
                else:
                    error_post_results("Dalton Agent Error in sensor \'%s\' while processing job %s. Error:\n%s" % (SENSOR_UID, JOB_ID, e))
                if DEBUG:
                    print "Non DaltonError Exception caught:\n%s" % e

            TOTAL_PROCESSING_TIME = int(int(time.time())-start_time)
            print_debug("Total Processing Time (includes job download time): %d seconds" % TOTAL_PROCESSING_TIME)

            # send results back to server
            status = send_results()

            # clean up
            # remove zip file
            os.unlink(zf_path)
            # remove job directory and contained files
            if not KEEP_JOB_FILES:
                shutil.rmtree(JOB_DIRECTORY)
            JOB_ID = None
        else:
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print "Keyboard Interrupt caught, exiting...."
        sys.exit(0)
    except DaltonError, e:
        if DEBUG:
            print "DaltonError caught (in while True loop):\n%s" % e
    except Exception, e:
        if DEBUG:
            print "General Dalton Agent exeption caught. Error:\n%s\n" % e
            traceback.print_exc()
        if JOB_ID:
            # unexpected error happened on agent when trying to process a job but there may not be job data so compile an empty response with the exception error message and try to send it
            if DEBUG:
                print "Possible communication error processing jobid %s.  Attempting to send error message to controller." % JOB_ID
            try:
                error_post_results(e)
                if DEBUG:
                    print "Successfully sent error message to controller for jobid %s" % JOB_ID
            except Exception, e:
                if DEBUG:
                    print "Could not communicate with controller to send error info for jobid %s; is the Dalton Controller accepting network communications? Error:\n%s" % (JOB_ID, e)
                time.sleep(ERROR_SLEEP_TIME)
        else:
            print "Agent Error -- Is the Dalton Controller accepting network communications?"
            sys.stdout.flush()
            time.sleep(ERROR_SLEEP_TIME)
