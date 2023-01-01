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

"""
Dalton Agent - runs on IDS engine; receives jobs, runs them, and reports results.
"""
#
# Note: originally written to run on Python 2.4 and up without the need for
# non-standard libararies so that is why some things are written the way
# they are. This is especially noticeable (painful?) with the use of urllib2
# instead of urllib3 or Requests.
#
# July 2019 - updated to run on Python 3.8 but many legacy code practices
# still present.
#

import os
import sys
import traceback
import urllib.request, urllib.parse, urllib.error
import urllib.request, urllib.error, urllib.parse
import re
import time
import datetime
import glob
import shutil
import base64
import json
import subprocess
import zipfile
import configparser
from optparse import OptionParser
import struct
import socket
import logging
from logging.handlers import RotatingFileHandler
from distutils.version import LooseVersion
import binascii
import hashlib
from pathlib import Path

# urllib2 in Python < 2.6 doesn't support setting a timeout so doing it like this
socket.setdefaulttimeout(120)

# Hard code this since Controller hard codes it.
# Used particularly for logging suri output when using socket control
suricata_logging_outputs_file = "/tmp/dalton-suricata.log"

# Also hard-coded; no need to expose but putting in variable for convenience.
suricata_sc_pid_file = "/usr/local/var/run/suricata.pid"


#*********************************
#*** Parse Command Line Options ***
#*********************************
parser = OptionParser()
parser.add_option("-c", "--config",
                    dest="configfile",
                    help="path to config file [default: %default]",
                    default="dalton-agent.conf")
(options, args) = parser.parse_args()

dalton_config_file = options.configfile

# get options from dalton config file
config = configparser.ConfigParser()

if not os.path.exists(dalton_config_file):
    # just print to stdout; logging hasn't started yet
    print(f"Config file '{dalton_config_file}' does not exist.\n\nexiting.")
    sys.exit(1)

try:
    config.read(dalton_config_file)
except Exception as e:
    # just print to stdout; logging hasn't started yet
    print(f"Error reading config file, '{dalton_config_file}'.\n\nexiting.")
    sys.exit(1)

try:
    DEBUG = config.getboolean('dalton', 'DEBUG')
    STORAGE_PATH = config.get('dalton', 'STORAGE_PATH')
    SENSOR_CONFIG = config.get('dalton', 'SENSOR_CONFIG')
    SENSOR_ENGINE = config.get('dalton', 'SENSOR_ENGINE').lower()
    SENSOR_ENGINE_VERSION = config.get('dalton', 'SENSOR_ENGINE_VERSION').lower()
    SENSOR_UID = config.get('dalton', 'SENSOR_UID')
    DALTON_API = config.get('dalton', 'DALTON_API')
    API_KEY = config.get('dalton', 'API_KEY')
    POLL_INTERVAL = int(config.get('dalton', 'POLL_INTERVAL'))
    KEEP_JOB_FILES = config.getboolean('dalton', 'KEEP_JOB_FILES')
    USE_SURICATA_SOCKET_CONTROL = config.getboolean('dalton', 'USE_SURICATA_SOCKET_CONTROL')
    SURICATA_SC_PYTHON_MODULE = config.get('dalton', 'SURICATA_SC_PYTHON_MODULE')
    SURICATA_SOCKET_NAME = config.get('dalton', 'SURICATA_SOCKET_NAME')

except Exception as e:
    # just print to stdout; logging hasn't started yet
    print(f"Error parsing config file, '{dalton_config_file}':\n\n{e}\n\nexiting.")
    sys.exit(1)

SENSOR_ENGINE_VERSION_ORIG = 'undefined'

#***************
#*** Logging ***
#***************

file_handler = RotatingFileHandler('/var/log/dalton-agent.log', 'a', 1 * 1024 * 1024, 10)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
logger = logging.getLogger("dalton-agent")
logger.addHandler(file_handler)
if DEBUG or ("AGENT_DEBUG" in os.environ and int(os.getenv("AGENT_DEBUG"))):
    file_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    logger.debug("DEBUG logging enabled")
else:
    file_handler.setLevel(logging.INFO)
    logger.setLevel(logging.INFO)


#************************************************
#** Helper Functions to populate config values **
#************************************************
def prefix_strip(mystring, prefixes=["rust_"]):
    """ strip passed in prefixes from the beginning of passed in string and return it
    """
    if not isinstance(prefixes, list):
        prefixes = [prefixes]
    for prefix in prefixes:
        if mystring.startswith(prefix):
            return mystring[len(prefix):]
    return mystring

def find_file(name):
    """Returns full path to file if found on system."""
    ret_path = None
    try:
        # see if it is already in the path by using the 'which' command
        process = subprocess.Popen("which %s" % name, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        if stderr:
            raise
        else:
            ret_path = stdout.decode('utf-8').strip()
    except:
        # file not in PATH, try manually searching
        paths = ['/usr/sbin', '/usr/bin', '/usr/local/bin', '/usr/local/sbin']
        for path in paths:
            candidate = os.path.join(path, name)
            if os.path.exists(candidate):
                ret_val = candidate
                break
    return ret_path

def get_engine_version(path):
    """returns the version of the engine given full path to binary (e.g. Suricata, Snort)."""
    global SENSOR_ENGINE_VERSION_ORIG
    engine = "unknown"
    version = "unknown"
    try:
        process = subprocess.Popen("%s -V" % path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout, stderr = process.communicate()
        regex = re.compile(r"(Version|(Suricata|zeek) version)\s+(?P<version>\d+[\d\x2E\x2D\5FA-Za-z]*)")
        if stderr:
            # apparently 'Snort -V' outputs to stderr....
            output = stderr
        else:
            output = stdout
        # get engine from output
        if "Suricata" in output.decode('utf-8'):
            engine = "suricata"
        elif "Snort" in output.decode('utf-8'):
            engine = "snort"
        elif "zeek" in output.decode('utf-8'):
            engine = "zeek"
        else:
            # use filenname of binary
            engine = os.path.basename(path).lower()
            logger.warn("Could not determine engine name, using '%s' from IDS_BINARY path" % engine)

        # get version from output
        result = regex.search(output.decode('utf-8'))
        if result:
            version = result.group('version')

        SENSOR_ENGINE_VERSION_ORIG = version

        # if Suricata version 4, see if Rust is enabled and add to version string
        if "suricata" in engine  and version.split('.')[0] == "4":
            process = subprocess.Popen('%s --build-info | grep "Rust support"' % path, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout, stderr = process.communicate()
            if "yes" in str(stdout):
                # rust support exists
                version = "rust_%s" % version
    except Exception as e:
        logger.warn("Exception in get_engine_version(): %s" % e)
        pass
    logger.debug("Using IDS binary '%s': engine: '%s', version '%s'" % (path, engine, version))
    return (engine, version)

def hash_file(filenames):
    """Returns md5sum of pased in file. If a list of files is passed,
       they are concatenated together and hashed.
       Remove "default-rule-path" from Suricata config since this
       changes every job.
    """
    if not isinstance(filenames, list):
        filenames = [filenames]
    hash = hashlib.md5()
    for filename in filenames:
        if not os.path.isfile(filename):
            logger.error(f"in hash_file(): file '{filename}' does not exit.")
            raise
        if filename.endswith(".yaml"):
            # remove "default-rule-path:" line
            with open(filename, 'r') as fh:
                lines = fh.readlines()
                hash.update("".join([l for l in lines if not l.startswith("default-rule-path:")]).encode('utf-8'))
        else:
            with open(filename, 'rb') as fh:
                data = fh.read(65536)
                while len(data) > 0:
                    hash.update(data)
                    data = fh.read(65536)
    return hash.hexdigest()

#**************************
#*** Constant Variables ***
#**************************

AGENT_VERSION = "3.1.1"
HTTP_HEADERS = {
    "User-Agent" : f"Dalton Agent/{AGENT_VERSION}"
}

# check options from config file
# done here after logging has been set up
if SENSOR_UID == 'auto':
    SENSOR_UID = socket.gethostname()

TCPDUMP_BINARY = 'auto'
try:
    TCPDUMP_BINARY = config.get('dalton', 'TCPDUMP_BINARY')
except Exception as e:
    logger.warn("Unable to get config value 'TCPDUMP_BINARY': %s" % e)
    pass
if TCPDUMP_BINARY == 'auto':
    TCPDUMP_BINARY = find_file('tcpdump')
if not TCPDUMP_BINARY or not os.path.exists(TCPDUMP_BINARY):
        logger.warn("Could not find 'tcpdump' binary.")
        TCPDUMP_BINARY = ''

IDS_BINARY = 'auto'
try:
    IDS_BINARY = config.get('dalton', 'IDS_BINARY')
except Exception as e:
    logger.warn("Unable to get config value 'IDS_BINARY': %s" % e)
    pass
if IDS_BINARY == 'auto':
    IDS_BINARY = find_file('suricata')
if not IDS_BINARY or not os.path.exists(IDS_BINARY):
        logger.info("Could not find 'suricata' binary, going to look for Snort.")
        IDS_BINARY = None
if IDS_BINARY is None:
    # look for Snort
    IDS_BINARY = find_file('snort')
    if not IDS_BINARY or not os.path.exists(IDS_BINARY):
        logger.info("Could not find 'snort' binary.")
        IDS_BINARY = None
if IDS_BINARY is None:
    # look for Zeek
    IDS_BINARY = find_file('zeek')
    if not IDS_BINARY or not os.path.exists(IDS_BINARY):
        logger.info("Could not find 'snort' binary.")
        logger.critical("No IDS binary specified or found.  Cannot continue.")
        sys.exit(1)

(eng, eng_ver) = get_engine_version(IDS_BINARY)
if SENSOR_ENGINE == "auto":
    SENSOR_ENGINE = eng
if SENSOR_ENGINE_VERSION == "auto":
    SENSOR_ENGINE_VERSION = eng_ver
if SENSOR_CONFIG == "auto":
    sensor_config_variable = ""
else:
    sensor_config_variable = f"SENSOR_CONFIG={SENSOR_CONFIG}&"

if not SENSOR_ENGINE.startswith("suricata"):
    USE_SURICATA_SOCKET_CONTROL = False

if USE_SURICATA_SOCKET_CONTROL:
    # Socket Control supported in Suricata 1.4 and later
    if float('.'.join(prefix_strip(eng_ver).split('.')[:2])) < 3.0:
        msg = f"Dalton Agent does not support Suricata Socket Control for Suricata versions before 3.0. This is running Suricata version {eng_ver}.  Disabling Suricata Socket Control Mode."
        logger.warn(msg)
        USE_SURICATA_SOCKET_CONTROL = False

if USE_SURICATA_SOCKET_CONTROL:
    if os.path.isdir(SURICATA_SC_PYTHON_MODULE):
        sys.path.append(SURICATA_SC_PYTHON_MODULE)
    elif os.path.isdir(os.path.abspath(os.path.join(SURICATA_SC_PYTHON_MODULE, '..', 'scripts', 'suricatasc', 'src'))):
        # older Suricata versions had suricatasc in "scripts" directory, not "python" directory
        sys.path.append(os.path.abspath(os.path.join(SURICATA_SC_PYTHON_MODULE, '..', 'scripts', 'suricatasc', 'src')))
    # Used as Suricata default-log-dir when in SC mode
    os.makedirs(os.path.dirname(SURICATA_SOCKET_NAME), exist_ok=True)

req_job_url = (f"{DALTON_API}/request_job?"
               f"SENSOR_ENGINE={SENSOR_ENGINE}&"
               f"SENSOR_ENGINE_VERSION={SENSOR_ENGINE_VERSION}&"
               f"SENSOR_UID={SENSOR_UID}&"
               f"AGENT_VERSION={AGENT_VERSION}&"
               f"{sensor_config_variable}"
               f"API_KEY={API_KEY}"
              )

logger.info("\n*******************")
logger.info("Starting Dalton Agent version %s:"% AGENT_VERSION)
logger.debug("\tDEBUG logging: enabled")
logger.info("\tSENSOR_UID: %s" % SENSOR_UID)
logger.info("\tSENSOR_ENGINE: %s" % SENSOR_ENGINE)
logger.info("\tSENSOR_ENGINE_VERSION: %s" % SENSOR_ENGINE_VERSION)
logger.info("\tSENSOR_CONFIG: %s" % SENSOR_CONFIG)
logger.info("\tIDS_BINARY: %s" % IDS_BINARY)
logger.info("\tTCPDUMP_BINARY: %s" % TCPDUMP_BINARY)
if SENSOR_ENGINE.startswith("suricata"):
    logger.info("\tSURICATA_SOCKET_CONTROL Support: %s" % USE_SURICATA_SOCKET_CONTROL)

# just in case the Dalton Agent is set to use a proxy, exclude "dalton_web" which is the
# web server container and communication with it shouldn't go thru a proxy; if the
# agent is contacting the hostname "dalton_web", then the agent and web server are
# containers on the same host.
dalton_web_container = "dalton_web"
if not 'no_proxy' in os.environ:
    os.environ['no_proxy'] = dalton_web_container
else:
    os.environ['no_proxy'] = "%s,%s" % (os.environ['no_proxy'].rstrip(','), dalton_web_container)
logger.info("Added '%s' to 'no_proxy' environment variable." % dalton_web_container)

#************************
#*** Global Variables ***
#************************
JOB_ID = None
PCAP_FILES = []
PCAP_DIR = "pcaps"
IDS_RULES_FILES = None
IDS_CONFIG_FILE = None
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
JOB_EVE_LOG = None
JOB_ZEEK_JSON = False
# end dalton's logs

# used by Snort for logs/alerts
# Suricata puts every log in here
IDS_LOG_DIRECTORY = None
TOTAL_PROCESSING_TIME = ''
# seconds
ERROR_SLEEP_TIME = 5
URLLIB_TIMEOUT = 120

# global class used for Suricata Socket Control
# set later
SCONTROL = None
# boolean used to work around Suricata Redmine issue 4225
SC_FIRST_RUN = True

#****************#
#*** Job Logs ***#
#****************#
# functions for populating job logs
def print_error(msg):
    if JOB_ERROR_LOG:
        fh = open(JOB_ERROR_LOG, "a")
        fh.write("%s\n" % msg)
        fh.close()
    else:
        logger.debug("print_error() called but no JOB_ERROR_LOG exists")
    print_msg("ERROR!")
    print_debug("ERROR:\n%s" % msg)
    # throw error
    raise DaltonError(msg)

def print_msg(msg):
    print_debug(msg)
    # send message
    logger.debug(msg)
    send_update(msg, JOB_ID)

def print_debug(msg):
    global JOB_DEBUG_LOG
    if JOB_DEBUG_LOG:
        fh = open(JOB_DEBUG_LOG, "a")
        fh.write("*****\n%s\n" % msg)
        fh.close()
    else:
        logger.debug("print_debug() called but no JOB_DEBUG_LOG exists")

#**********************
#*** Custom Classes ***
#**********************

class SocketController:
    """ Basically a wrapper for Suricata socket control.
        Also handles start/restart of Suricata which is
        run in daemon mode.
    """
    def __init__(self, socket_path):
        try:
            self.sc = suricatasc.SuricataSC(socket_path)
            self.ruleset_hash = None
            self.config_hash = None
            self.reset_logging()
            self.suricata_is_running = False
        except Exception as e:
            print_error("Problem initializing Suricata socket control: %s" % e)

    def connect(self):
        try:
            logger.debug("Connecting to socket...")
            self.sc.connect()
        except Exception as e:
            self.suricata_is_running = False
            logger.debug("%s" % traceback.format_exc())
            print_error("Problem connecting to Unix socket: %s" % e)
            try:
                self.close()
            except Exception as e:
                print_debug(f"... unable to close Unix socket: {e}")

    def send_command(self, command):
        try:
            cmd, arguments = self.sc.parse_command(command)
            #logger.debug("in send_command():\n\tcmd: %s\n\targuments: %s" % (cmd, arguments))
            cmdret = self.sc.send_command(cmd, arguments)
        except Exception as e:
            print_error("Problem parsing/sending command: %s" % e)

        if cmdret["return"] == "NOK":
            print_error("\"NOK\" response received from socket command; message: %s" % json.dumps(cmdret["message"]))

        return json.dumps(cmdret["message"])

    def close(self):
        """Close socket connection."""
        self.sc.close()
        logger.debug("Closed connection to socket.")

    def shutdown(self):
        """Shutdown Suricata process."""
        logger.debug("Shutting down Suricata Unix Socket instance.")
        try:
            self.send_command("shutdown")
        except Exception as e:
            print_error(f"Problem shutting down Suricata instance in shutdown(): {e}")
        finally:
            self.suricata_is_running = False


    def stop_suricata_daemon(self):
        """Stop Suricata daemon using socket control."""
        logger.debug("stop_suricata_daemon() called")
        if not self.suricata_is_running:
            logger.warn("stop_suricata_daemon() called but Suricata may not be running."
                        " Still attempting shutdown but it will likely error."
                       )
        try:
            self.connect()
            self.shutdown()
            self.close()
        except Exception as e:
            print_error(f"Problem shutting down old Suricata instance in stop_suricata_daemon(): {e}")
        finally:
            self.suricata_is_running = False

    def reset_logging(self, delete_pid_file = True):
        """ Reset log files and remove pid file if exists. """
        # logging
        if os.path.exists(suricata_logging_outputs_file):
            logger.debug("deleting '%s'" % suricata_logging_outputs_file)
            os.unlink(suricata_logging_outputs_file)
        # touch file since it gets read at Suri startup in daemon mode and
        # there could be a race condition
        Path(suricata_logging_outputs_file).touch()
        self.log_offset = 0
        self.suri_startup_log = ''

        # pid file
        if delete_pid_file:
            if os.path.exists(suricata_sc_pid_file):
                logger.debug("deleting '%s'" % suricata_sc_pid_file)
                os.unlink(suricata_sc_pid_file)

    def start_suricata_daemon(self, config):
        """Start Suricata thread with Unix Socket listener."""
        logger.debug("start_suricata_daemon() called")
        self.reset_logging()
        if config is None:
            print_error("start_suricata_daemon() called but not initialized.")
        # start Suri
        suricata_command = f"suricata -c {config} -k none --runmode single --unix-socket={SURICATA_SOCKET_NAME} -D"
        print_debug(f"Starting suricata thread with the following command:\n{suricata_command}")
        # use Popen() instead of call() since the latter blocks which isn't what we want
        subprocess.Popen(suricata_command, shell = True)
        # wait for Suricata to be ready to process traffic before returning
        # tail suricata_logging_outputs_file (default /tmp/dalton-suricata.log),
        # look for "engine started."
        with open(suricata_logging_outputs_file, 'r') as suri_output_fh:
            logger.debug("tailing '%s' to see when engine has started up fully" % suricata_logging_outputs_file)
            now = datetime.datetime.now()
            keep_looking = True
            while keep_looking:
                line = suri_output_fh.readline()
                if not line or not line.endswith('\n'):
                    time.sleep(0.1)
                    continue
                self.suri_startup_log += line
                if "engine started" in line.lower():
                    self.log_offset = suri_output_fh.tell()
                    break
                if "<Error>" in line:
                    # submit_job() errors out before JOB_IDS_LOG is copied so
                    # copy over output log to JOB_IDS_LOG here so it gets returned
                    shutil.copyfile(suricata_logging_outputs_file, JOB_IDS_LOG)
                    self.suricata_is_running = False
                    print_error(f"Problem starting Suricata daemon: {line}")
                else:
                    new_now = datetime.datetime.now()
                    if (new_now - now).seconds > 120:
                        # timeout
                        shutil.copyfile(suricata_logging_outputs_file, JOB_IDS_LOG)
                        self.suricata_is_running = False
                        print_error("Timeout waiting on Suricata daemon to start.")

        self.suricata_is_running = True
        logger.debug("Suricata daemon started")

    def restart_suricata_socket_mode(self, newconfig):
        global SC_FIRST_RUN
        if self.suricata_is_running:
            # Suricata daemon is running; stop it so we can start
            # a new one with a new config and/or rules
            self.stop_suricata_daemon()
        SCONTROL.start_suricata_daemon(newconfig)
        SC_FIRST_RUN = True

# Error Class
class DaltonError(Exception):
    pass

#***********************
#*** Custom Imports ****
#***********************

if USE_SURICATA_SOCKET_CONTROL:
    try:
        import suricatasc
    except Exception as e:
        logger.error(f"Unable to import 'suricatasc' module (SURICATA_SC_PYTHON_MODULE set to '{SURICATA_SC_PYTHON_MODULE}'). Suricata Socket Control will be disabled.")
        USE_SURICATA_SOCKET_CONTROL = False

#****************************************
#*** Communication/Printing Functions ***
#****************************************
def send_update(msg, job_id = None):
    global DALTON_API
    global SENSOR_UID
    global HTTP_HEADERS
    global API_KEY

    url = f"{DALTON_API}/update/?apikey={API_KEY}"

    params = {}
    params['uid'] = SENSOR_UID
    params['msg'] = msg
    params['job'] = job_id

    req = urllib.request.Request(url, urllib.parse.urlencode(params).encode('utf-8'), HTTP_HEADERS)
    try:
        urllib.request.urlopen(req, timeout=URLLIB_TIMEOUT)
    except Exception as e:
        raise Exception(f"Error in sensor '{SENSOR_UID}' while processing job {job_id}. "
                        "Could not communicate with controller in send_update().\n\tAttempted URL:\n\t"
                        + re.sub(r'\x26API_KEY=[^\x26]+', "", url)
                       )

def request_job():
    try:
        data = urllib.request.urlopen(req_job_url, timeout=URLLIB_TIMEOUT).read().decode('utf-8')
    except Exception as e:
        raise Exception(f"Error in sensor '{SENSOR_UID}'. "
                        "Could not communicate with controller in request_job().\n\tAttempted URL:\n\t"
                        + re.sub(r'\x26API_KEY=[^\x26]+', "", req_job_url)
                       )

    if (data == 'sleep'):
        #sleep
        return None
    else:
        #we got a job?
        try:
            job = json.loads(data)
        except Exception as e:
            print_error(f"Problem loading json from Dalton Controller; could not parse job id from data: '{data}'.")
        return job

def request_zip(jid):
    url = f"{DALTON_API}/get_job/{jid}?apikey={API_KEY}"
    params = {}

    req = urllib.request.Request(url, None, HTTP_HEADERS)
    try:
        zf = urllib.request.urlopen(req, timeout=URLLIB_TIMEOUT)
    except Exception as e:
        raise Exception(f"Error in sensor '{SENSOR_UID}'. "
                         "Could not communicate with controller in request_zip().\n\tAttempted URL:\n\t"
                         + re.sub(r'\x26API_KEY=[^\x26]+', "", url)
                       )

    zf_path = f"{STORAGE_PATH}/{jid}.zip"

    f = open(zf_path,'wb')
    f.write(zf.read())
    f.close()
    return zf_path

# takes a re match object (should be a single byte) and returns it
# as printable.  Example: byte 0x13 becomes string "\x13".
def hexescape(matchobj):
    return r'\x{0:02x}'.format(ord(matchobj.group()))

# send results back to server.  Returns value of 'status' in results dictionary
def send_results():
    print_debug("send_results() called")
    print_msg("Sending back results")

    nonprintable_re = re.compile(r'[\x80-\xFF]')

    # create and populate results dictionary
    results_dict = {}

    # populate error and status
    fh = open(JOB_ERROR_LOG, 'r')
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
    with open(JOB_IDS_LOG, 'r') as fh:
        results = fh.read()
    if not results:
        results_dict['ids'] = "*** No Output ***\n"
    else:
        # make sure we have only ASCII
        results_dict['ids'] = ""
        for line in results:
            results_dict['ids'] += nonprintable_re.sub(hexescape, line)

    # populate alert
    fh = open(JOB_ALERT_LOG, 'r')
    results = fh.read()
    if not results:
        results_dict['alert'] = "*** No Alerts ***\n"
    else:
        results_dict['alert'] = results
    fh.close()

    # populate alert detailed
    fh = open(JOB_ALERT_DETAILED_LOG, 'r')
    results = fh.read()
    fh.close()
    if not results: # or error identified in results?
        results_dict['alert_detailed'] = ""
    else:
        results_dict['alert_detailed'] = results

    # populate performance
    fh = open(JOB_PERFORMANCE_LOG, 'r')
    results = fh.read()
    results_dict['performance'] = results
    fh.close()

    # populate debug
    fh = open(JOB_DEBUG_LOG, 'r')
    results = fh.read()
    results_dict['debug'] = results
    fh.close()

    # populate TOTAL_PROCESSING_TIME
    results_dict['total_time'] = TOTAL_PROCESSING_TIME

    # populate other logs (Suricata only for now)
    # this file actually contains json; Dalton controller will have to (double) decode since
    # results_dict is json encoded before it is sent
    fh = open(JOB_OTHER_LOGS, 'r')
    results = fh.read()
    results_dict['other_logs'] = results
    fh.close()

    # populate EVE log
    fh = open(JOB_EVE_LOG, 'r')
    results = fh.read()
    results_dict['eve'] = results
    fh.close()

    # set Zeek JSON
    results_dict['zeek_json'] = JOB_ZEEK_JSON

    #comment this out for prod
    #logger.debug(results_dict)

    # convert the dictionary to json
    json_results_dict = json.dumps(results_dict)

    #comment this out for prod
    #logger.debug(json_results_dict)

    payload = {'json_data': json_results_dict}
    # send results back to server
    post_results(payload)
    return results_dict['status']

def post_results(json_data):
    #logger.debug("json_data:\n%s" % json_data)
    url = "%s/results/%s?SENSOR_UID=%s&apikey=%s" % (DALTON_API, JOB_ID, SENSOR_UID, API_KEY)
    req = urllib.request.Request(url, urllib.parse.urlencode(json_data).encode('utf-8'), HTTP_HEADERS)
    try:
        response = urllib.request.urlopen(req, timeout=URLLIB_TIMEOUT)
    except Exception as e:
        try:
            truncated_url = re.search('(^[^\?]*)', url).group(1)
        except:
            truncated_url = "unknown"

        raise Exception(f"Error in sensor '{SENSOR_UID}' while processing job {job_id}"
                        "Could not communicate with controller in post_results().\n\tAttempted URL:\n\t"
                        + re.sub(r'\x26API_KEY=[^\x26]+', "", url)
                        + "\n\tError:\n\t"
                        + f"{e}"
                       )

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

# process alert output from Snort
def process_snort_alerts():
    print_debug("process_snort_alerts() called")
    print_msg("Processing alerts")
    os.system("chmod -R 755 %s" % IDS_LOG_DIRECTORY)

    job_alert_log_fh = open(JOB_ALERT_LOG, "w")
    for alert_file in glob.glob(os.path.join(IDS_LOG_DIRECTORY, "alert-full_dalton-agent*")):
        alert_filehandle = open(alert_file, "r")
        print_debug("Processing snort alert file %s" % alert_file)
        job_alert_log_fh.write(alert_filehandle.read())
        alert_filehandle.close()
    job_alert_log_fh.close()

def check_pcaps():
    """
    Check of the pcaps and alert on potential issues.
    Add other checks here as needed.
    """
    print_debug("check_pcaps() called")

    # Check of the pcaps to make sure none were submitted with TCP packets but no TCP packets have the SYN flag
    # only call if no alerts fired
    if os.path.getsize(JOB_ALERT_LOG) == 0:
        try:
            if os.path.exists(TCPDUMP_BINARY):
                for pcap in PCAP_FILES:
                    # check for TCP packets
                    if len(subprocess.Popen("%s -nn -q -c 1 -r %s -p tcp 2>/dev/null" % (TCPDUMP_BINARY, pcap), shell=True, stdout=subprocess.PIPE).stdout.read()) > 0:
                        # check for SYN packets; this only works on IPv4 packets
                        if len(subprocess.Popen("%s -nn -q -c 1 -r %s \"tcp[tcpflags] & tcp-syn != 0\" 2>/dev/null" % (TCPDUMP_BINARY, pcap), shell=True, stdout=subprocess.PIPE).stdout.read()) == 0:
                            # check IPv6 packets too
                            if len(subprocess.Popen("%s -nn -q -c 1 -r %s \"ip6 and tcp and ip6[0x35] & 0x2 != 0\" 2>/dev/null" % (TCPDUMP_BINARY, pcap), shell=True, stdout=subprocess.PIPE).stdout.read()) == 0:
                                print_error("As Dalton says, \"pain don\'t hurt.\" But an incomplete pcap sure can."
                                            "\n\n"
                                            "The pcap file \'%s\' contains TCP traffic but does not "
                                            "contain any TCP packets with the SYN flag set."
                                            "\n\n"
                                            "Almost all IDS rules that look for TCP traffic require "
                                            "an established connection.\nYou will need to provide a more complete "
                                            "pcap if you want accurate results."
                                            "\n\n"
                                            "If you need help crafting a pcap, Flowsynth may be able to help --\n"
                                            "https://github.com/secureworks/flowsynth"
                                            "\n\n"
                                            "And, \"there's always barber college....\"" % os.path.basename(pcap))
            else:
                print_debug("In check_pcaps() -- no tcpdump binary found at %s" % TCPDUMP_BINARY)
        except Exception as e:
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
            with open(pcap, 'rb') as fh:
                bytes = fh.read(44)

            magic = binascii.hexlify(bytes[0:4]).decode('ascii')
            if magic.lower() == '0a0d0d0a':
                # this is pcapng and these aren't the byte-order magic bytes
                snaplen_offset = 40
                pcapng = True
                # get the correct byte-order magic bytes for pcapng
                magic = binascii.hexlify(bytes[8:12]).decode('ascii')
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
    except Exception as e:
        if not str(e).startswith("Warning:"):
            print_debug("Error doing snaplen check in check_pcaps(): %s" % e)

#*************************
#**** Snort Functions ****
#*************************
def run_snort():
    print_debug("run_snort() called")
    IDS_BUFFERS_LOG = os.path.join(IDS_LOG_DIRECTORY, "dalton-buffers.log")
    # note: if we don't have '--treat-drop-as-alert' then some alerts in a stream that has already triggered a 'drop' rule won't fire since they are assumed to already blocked by the DAQ
    snort_command = "%s -Q --daq dump --daq-dir /usr/lib/daq/ --daq-var load-mode=read-file --daq-var file=/tmp/inline-out.pcap -l %s -c %s -k none -X --conf-error-out --process-all-events --treat-drop-as-alert --pcap-dir=%s --buffer-dump-alert=%s 2>&1" % (IDS_BINARY, IDS_LOG_DIRECTORY, IDS_CONFIG_FILE, os.path.split(PCAP_FILES[0])[0], IDS_BUFFERS_LOG)
    print_msg("Starting Snort and Running Pcap(s)...")
    print_debug("Running Snort with the following command command:\n%s" % snort_command)
    snort_output_fh = open(JOB_IDS_LOG, "w")
    subprocess.call(snort_command, shell =  True, stderr=subprocess.STDOUT, stdout=snort_output_fh)
    snort_output_fh.close()

#************************
#** Suricata Functions **
#************************


def run_suricata_sc():
    global SCONTROL, SC_FIRST_RUN

    print_debug("Using Suricata Socket Control ... run_suricata_sc() called")
    if not IDS_BINARY:
        print_error("No Suricata binary found on system.")
    print_msg("Running pcap(s) thru Suricata; using socket control")
    config_hash = hash_file(IDS_CONFIG_FILE)
    ruleset_hash = hash_file(sorted(glob.glob(os.path.join(JOB_DIRECTORY, "*.rules"))))
    logger.debug("NEW config_hash: %s, ruleset_hash: %s" % (config_hash, ruleset_hash))
    logger.debug("OLD config_hash: %s, ruleset_hash: %s" % (SCONTROL.config_hash, SCONTROL.ruleset_hash))
    if (not (ruleset_hash == SCONTROL.ruleset_hash and config_hash == SCONTROL.config_hash)) \
        and SCONTROL.suricata_is_running:
        # if hashes don't match, shutdown suri via socket, start new suri, update hashes, run
        print_debug("Suricata Socket Control: new hashes found, restarting Suricata.....")
        SCONTROL.ruleset_hash = ruleset_hash
        SCONTROL.config_hash = config_hash
        SCONTROL.restart_suricata_socket_mode(newconfig=IDS_CONFIG_FILE)
    else:
        if not SCONTROL.suricata_is_running:
            logger.warn("Suricata thread not running ... starting it back up....")
            SCONTROL.ruleset_hash = ruleset_hash
            SCONTROL.config_hash = config_hash
            SCONTROL.restart_suricata_socket_mode(newconfig=IDS_CONFIG_FILE)
        else:
            print_debug("New job has same config and ruleset hash, not restarting.")

    SCONTROL.connect()
    if SC_FIRST_RUN:
        bug4225_versions = ["5.0.5", "5.0.6", "5.0.7", "6.0.1", "6.0.2", "6.0.3", "7.0.0-dev"]
        if SENSOR_ENGINE_VERSION_ORIG in bug4225_versions:
            # Re: https://redmine.openinfosecfoundation.org/issues/4225
            # Certain Suricata versions will throw an error on the
            # first (after starting up) attempt to run a pcap using
            # the socket control pcap-file command if
            # 'anomaly' logger and/or 'drop' logger are enabled.
            # To work around this for now, we make an initial dummy "pcap-file"
            # request with a small benign pcap so the error condition can
            # work itself out.
            dummy_pcap_bytes = b'\xD4\xC3\xB2\xA1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00' \
                               b'\xFF\xFF\x00\x00\x01\x00\x00\x00\x20\xD0\x23\x60\x84\xE8\x0C\x00' \
                               b'\x2B\x00\x00\x00\x2B\x00\x00\x00\x53\x07\x1D\x71\x7F\xB3\xCB\xDA' \
                               b'\x12\x16\x20\xAF\x08\x00\x45\x00\x00\x1D\x00\x01\x00\x00\x40\x11' \
                               b'\xB0\x32\xC0\xA8\x7A\x95\xAC\x10\xE3\x4E\x1F\x48\x05\x39\x00\x09' \
                               b'\xCC\xBD\x44'
            dummy_pcap_file = "/tmp/dalton-dummy-pcap"
            with open(dummy_pcap_file, "wb") as dfh:
                dfh.write(dummy_pcap_bytes)
            logger.debug("Sending dummy pcap to socket control to work around Redmine 4225")
            resp = SCONTROL.send_command(f"pcap-file {dummy_pcap_file} /tmp")
            logger.debug(f"Sent dummy pcap. Response: {resp}")
            while int(SCONTROL.send_command("pcap-file-number")) > 0 or SCONTROL.send_command("pcap-current") != "\"None\"":
                # wait for dummy pcap run to finish
                # TODO: check for timeout/infinite loop?
                time.sleep(.05)
            SC_FIRST_RUN = False
            # skip over output from dummy pcap run in global suri output log
            with open(suricata_logging_outputs_file, 'r') as fh:
                fh.seek(SCONTROL.log_offset, 0)
                fh.read()
                SCONTROL.log_offset = fh.tell()

    # queue up the real pcaps
    for pcap in PCAP_FILES:
        resp = SCONTROL.send_command(f"pcap-file {pcap} {IDS_LOG_DIRECTORY}")
        logger.debug("Sent pcap %s. Response: %s" % (pcap, resp))

    # pcap files submitted (non blocking, they get queued); wait until done
    # note that "pcap-file-number" command returns the number in the queue, and
    # does not inlude the current pcap being processed, so wait until that
    # ("pcap-current") is None.
    # TODO: check for timeout/infinite loop?
    files_remaining = 1
    current_pcap = "dummy.pcap"
    # TODO: change dynamically based on number of pcap files?
    sleep_time = .1
    while files_remaining > 0 or current_pcap != "\"None\"":
        time.sleep(sleep_time)
        # TODO: try/catch ???
        files_remaining = int(SCONTROL.send_command("pcap-file-number"))
        current_pcap = SCONTROL.send_command("pcap-current")
        #logger.debug(f"files_remaining: {files_remaining}, current_pcap: {current_pcap}")
    logger.debug("In run_suricata_sc(): all pcaps done running ... closing connection to socket.")
    SCONTROL.close()

def run_suricata():
    print_debug("run_suricata() called")
    if not IDS_BINARY:
        print_error("No Suricata binary found on system.")
    print_msg("Running pcap(s) thru Suricata")
    # some Suri versions don't support all modern options like '-k' so try to deal with that here
    add_options = ""
    try:
        if LooseVersion(SENSOR_ENGINE_VERSION_ORIG) >= LooseVersion("2.0"):
            # not sure if the '-k' option was added in Suri 2.0 or earlier but for now just doing this for v2 and later
            add_options = "-k none"
    except Exception as e:
        add_options = ""
    suricata_command = "%s -c %s -l %s %s " % (IDS_BINARY, IDS_CONFIG_FILE, IDS_LOG_DIRECTORY, add_options)
    if len(PCAP_FILES) > 1:
        suricata_command += "-r %s" % (os.path.dirname(PCAP_FILES[0]))
    else:
        suricata_command += "-r %s" % (PCAP_FILES[0])
    print_debug("Running suricata with the following command:\n%s" % suricata_command)
    suri_output_fh = open(JOB_IDS_LOG, "w")
    subprocess.call(suricata_command, shell = True, stderr=subprocess.STDOUT, stdout=suri_output_fh)
    suri_output_fh.close()


# generate fast pattern info; this requires a separate Suricata run
#   with the '--engine-analysis' flag set
def generate_fast_pattern():
    print_debug("generate_fast_pattern() called")
    print_msg("Generating Fast Pattern Info")
    if SENSOR_ENGINE.startswith('suri'):
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
    alerts_file = os.path.join(IDS_LOG_DIRECTORY, "dalton-fast.log")
    if os.path.exists(alerts_file):
        job_alert_log_fh = open(JOB_ALERT_LOG, "w")
        alert_filehandle = open(alerts_file, "r")
        for line in alert_filehandle:
            # can do alert formatting here if we want
            # for now just add newline between alerts
            job_alert_log_fh.write("%s\n" % line)
        alert_filehandle.close()
        job_alert_log_fh.close()
    else:
        print_debug("No alerts found. File \'%s\' does not exist." % alerts_file)

def process_eve_log():
    print_debug("process_eve_log() called")
    print_msg("Processing EVE JSON log")
    eve_file = os.path.join(IDS_LOG_DIRECTORY, "dalton-eve.json")
    if os.path.exists(eve_file):
        # just copy it; no processing needed at this time
        shutil.copyfile(eve_file, JOB_EVE_LOG)
        print_debug(f"copying {eve_file} to {JOB_EVE_LOG}")
    else:
        print_debug("No EVE JSON file found. File \'%s\' does not exist." % eve_file)

def process_other_logs(other_logs):
    """
    Takes a dictionary of Display Name, filename pairs for logs in the IDS_LOG_DIRECTORY and poulates
    the JOB_OTHER_LOGS with a dictionary containing the Display Name and file contents.
    """
    print_debug("process_other_logs() called")
    print_msg("Processing other logs")
    if len(other_logs) > 0:
        all_other_logs = {}
        for log_name in other_logs:
            if not os.path.exists("%s/%s" % (IDS_LOG_DIRECTORY, other_logs[log_name])):
                log_name_new = other_logs[log_name].replace("-", "_")
                if log_name_new != other_logs[log_name]:
                    print_debug("Log file \'%s\' not present, trying \'%s\'..." % (other_logs[log_name], log_name_new))
                    other_logs[log_name] = log_name_new
            if os.path.exists("%s/%s" % (IDS_LOG_DIRECTORY, other_logs[log_name])):
                log_fh = open("%s/%s" % (IDS_LOG_DIRECTORY, other_logs[log_name]), "r")
                all_other_logs[log_name] = log_fh.read()
                log_fh.close()
                if all_other_logs[log_name] == "":
                    print_debug("log \"%s\" is empty, not inclding" % log_name)
                    del all_other_logs[log_name]
            else:
                print_debug("Requested log file \'%s\' not present, skipping." % other_logs[log_name])
        other_logs_fh = open(JOB_OTHER_LOGS, "w")
        other_logs_fh.write(json.dumps(all_other_logs))
        other_logs_fh.close()
    else:
        print_debug("No additional logs requested.")

def check_for_errors(tech):
    """ checks the IDS output for error messages """
    print_debug("check_for_errors() called")
    error_lines = []
    try:
        ids_log_fh = open(JOB_IDS_LOG, "r")
        for line in ids_log_fh:
            if tech.startswith('suri'):
                if ("<Error>" in line or line.startswith("ERROR") or line.startswith("Failed to parse configuration file")):
                    error_lines.append(line)
                    if "bad dump file format" in line or "unknown file format" in line:
                        error_lines.append("Bad pcap file(s) submitted to Suricata. Pcap files should be in libpcap format (pcapng is not supported in older Suricata versions).\n")
            elif tech.startswith('snort'):
                if "ERROR:" in line or "FATAL" in line or "Fatal Error" in line or "Segmentation fault" in line or line.startswith("Error "):
                    error_lines.append(line)
                    if "unknown file format" in line:
                        error_lines.append("Bad pcap file(s) submitted to Snort. Pcap files should be in libpcap or pcapng format.\n")
            else:
                logger.warn(f"Unexpected engine value passed to check_for_errors(): {tech}")
        ids_log_fh.close()
    except Exception as e:
        print_error("Error reading IDS output file \'%s\'. Error:\n\n%s" % (JOB_IDS_LOG, e))

    if len(error_lines) > 0:
        print_error("Error message(s) found in IDS output. See \"IDS Engine\" tab for more details and/or context:\n\n%s" % '\n'.join(error_lines))

# process unified2 data and populate JOB_ALERT_DETAILED_LOG (only for sensors
# that generate unified2 logs such as Snort and Suricata)
# instead of decoding on the agent and sending it back (would
# require u2spewfoo or something like python idstools), just concatenate the
# files and send them back.  Because we use urllib2 and not something more
# full-featured like Requests, we have to send the data as
# www-form-urlencoded which means we have to base64 to for the transfer
# which means bloat.  Mixed part MIME would be better but at least
# we won't get as much URI encoding bloat as we would if we sent the text from decoded unified2.
def process_unified2_logs():
    print_debug("process_unified2_logs() called")
    print_msg("Processing unified2 logs")

    print_debug("Identifying unified2 log files...")
    unified2_files = set([])
    # unified2 filename set in config on submission
    for u2_file in glob.glob(os.path.join(IDS_LOG_DIRECTORY, "unified2.dalton.alert*")):
        print_debug("Adding unified2 alert file to processing list: %s" % u2_file)
        unified2_files.add(u2_file)
    if len(unified2_files) == 0:
        print_debug("No unified2 files found.")
        return
    # convert set to list so we can access indexes
    unified2_files = list(unified2_files)
    # now, cat all the files together, base64 encode them, and write to JOB_ALERT_DETAILED_LOG
    # copy first file instead of catting to it to preserve original on agent if needed
    u2_combined_file = os.path.join(IDS_LOG_DIRECTORY, "dalton-unified2-combined.alerts")
    shutil.copyfile(unified2_files[0], u2_combined_file)
    try:
        combined_fh = open(u2_combined_file, "ab")
        for i in range(1, len(unified2_files)):
            add_fh = open(unified2_files[i], "rb")
            combined_fh.write(add_fh.read())
            add_fh.close()
        combined_fh.close()
    except Exception as e:
        print_debug("Error processing unified2 files, bailing: %s" % e)
        return

    # b64 it and write!
    try:
        with open(JOB_ALERT_DETAILED_LOG, 'wb') as job_alert_detailed_log_fh:
            with  open(u2_combined_file, 'rb') as u2_fh:
                job_alert_detailed_log_fh.write(base64.b64encode(u2_fh.read()))
    except Exception as e:
        print_debug("Error processing unified2 files and base64 encoding them for transmission ... bailing. Error: %s" % e)
        return

# process performance output (Snort and Suricata)
def process_performance_logs():
    print_debug("process_performance_logs() called")
    print_msg("Processing performance logs")
    os.system("chmod -R 755 %s" % IDS_LOG_DIRECTORY)
    job_performance_log_fh = open(JOB_PERFORMANCE_LOG, "w")
    if len(glob.glob(os.path.join(IDS_LOG_DIRECTORY, "dalton-rule_perf*"))) > 0:
        for perf_file in glob.glob(os.path.join(IDS_LOG_DIRECTORY, "dalton-rule_perf*")):
            perf_filehandle = open(perf_file, "r")
            print_debug("Processing rule performance log file %s" % perf_file)
            job_performance_log_fh.write(perf_filehandle.read())
            job_performance_log_fh.write("\n")
            perf_filehandle.close()
    else:
        print_debug("No rules performance log(s) found. File \'%s\' does not exist." % "dalton-rule_perf*")
    job_performance_log_fh.close()


#************************
#**** Zeek Functions ****
#************************
def run_zeek(json_logs):
    print_debug("run_zeek() called")
    zeek_command = "cd %s && %s -C -r %s" % (IDS_LOG_DIRECTORY, IDS_BINARY, PCAP_FILES[0])
    if json_logs:
        zeek_command += " -e 'redef LogAscii::use_json=T;redef LogAscii::json_timestamps=JSON::TS_ISO8601;'"

    if len([f for f in os.listdir('/opt/dalton-agent/zeek_scripts/') if not f.startswith('.')]) > 0:
        zeek_command += " /opt/dalton-agent/zeek_scripts/*"

    print_msg("Starting Zeek and Running Pcap(s)...")
    print_debug("Running Zeek with the following command command:\n%s" % zeek_command)
    zeek_output_fh = open(JOB_IDS_LOG, "w")
    zeek_error_fh = open(JOB_ERROR_LOG, "w")
    subprocess.call(zeek_command, shell=True, stderr=zeek_error_fh, stdout=zeek_output_fh)
    zeek_output_fh.close()
    zeek_error_fh.close()

# process logs from Zeek
def process_zeek_logs():
    print_debug("process_zeek_logs() called")
    print_msg("Processing logs")
    os.system("chmod -R 755 %s" % IDS_LOG_DIRECTORY)

    logs = {}
    for log_file in os.listdir(IDS_LOG_DIRECTORY):
        logs[log_file.split('.')[0]] = log_file

    return logs


#****************************
#*** Submit Job Functions ***
#****************************
# resets the global variables between jobs
def reset_globals():
    global JOB_ID, PCAP_FILES, IDS_RULES_FILES, IDS_CONFIG_FILE, \
           JOB_DIRECTORY, JOB_LOG_DIRECTORY, JOB_ERROR_LOG, JOB_IDS_LOG, \
           JOB_DEBUG_LOG, JOB_ALERT_LOG, JOB_ALERT_DETAILED_LOG, JOB_PERFORMANCE_LOG, \
           IDS_LOG_DIRECTORY, TOTAL_PROCESSING_TIME, JOB_OTHER_LOGS, JOB_EVE_LOG, JOB_ZEEK_JSON

    JOB_ID = None
    PCAP_FILES = []
    IDS_RULES_FILES = []
    IDS_CONFIG_FILE = None
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
    JOB_EVE_LOG = None
    # end dalton's logs
    # used by snort for logs/alerts
    IDS_LOG_DIRECTORY = None
    TOTAL_PROCESSING_TIME = ''
    JOB_OTHER_LOGS = None
    JOB_ZEEK_JSON = False

# primary function
# gets passed directory of submitted files (rules file, pcap file(s)) and job ID
def submit_job(job_id, job_directory):
    global JOB_ID, PCAP_FILES, IDS_RULES_FILES, IDS_CONFIG_FILE, \
           JOB_DIRECTORY, JOB_LOG_DIRECTORY, JOB_ERROR_LOG, JOB_IDS_LOG, \
           JOB_DEBUG_LOG, JOB_ALERT_LOG, JOB_ALERT_DETAILED_LOG, JOB_OTHER_LOGS, \
           JOB_PERFORMANCE_LOG, IDS_LOG_DIRECTORY, TOTAL_PROCESSING_TIME, IDS_BINARY, \
           JOB_EVE_LOG, USE_SURICATA_SOCKET_CONTROL, JOB_ZEEK_JSON
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
    JOB_EVE_LOG = os.path.join(JOB_LOG_DIRECTORY, "dalton-eve.json")

    # touch log files
    open(JOB_ERROR_LOG, "w").close()
    open(JOB_IDS_LOG, "w").close()
    open(JOB_DEBUG_LOG, "w").close()
    open(JOB_ALERT_LOG, "w").close()
    open(JOB_ALERT_DETAILED_LOG, "w").close()
    open(JOB_OTHER_LOGS, "w").close()
    open(JOB_PERFORMANCE_LOG, "w").close()
    open(JOB_EVE_LOG, "w").close()

    print_debug(datetime.datetime.now().strftime("%b %d %Y %H:%M:%S"))
    print_debug(f"Agent Name: {SENSOR_UID}\nAgent Version: {AGENT_VERSION}\nIDS Engine: {SENSOR_ENGINE} {SENSOR_ENGINE_VERSION}\nDalton API: {DALTON_API}")

    print_debug("submit_job() called")

    # read manifest file
    manifest_data = []
    if os.path.exists("%s/manifest.json" % JOB_DIRECTORY):
        manifest_file = open("%s/manifest.json" % JOB_DIRECTORY, "r")
        for line in manifest_file:
            manifest_data.append(json.loads(line))
        manifest_file.close()
    print_debug("manifest.json: %s" % manifest_data)

    # use Suricata Socket Control (Suricata only)
    if SENSOR_ENGINE.startswith('suri'):
        try:
            useSuricataSC = manifest_data[0]['use-suricatasc']
            if useSuricataSC != USE_SURICATA_SOCKET_CONTROL:
                if useSuricataSC and float('.'.join(prefix_strip(SENSOR_ENGINE_VERSION_ORIG).split('.')[:2])) < 3.0:
                    msg = f"Dalton Agent does not support Suricata Socket Control for Suricata versions before 3.0. This is running Suricata version {eng_ver}.  Cannot use Suricata Socket Control Mode."
                    logger.warn(msg)
                    # should not be necessary but just in case
                    USE_SURICATA_SOCKET_CONTROL = False
                else:
                    msg = f"Changing Suricata Socket Control option to '{useSuricataSC}' per job settings."
                    logger.info(msg)
                    print_debug(msg)
                    USE_SURICATA_SOCKET_CONTROL = useSuricataSC
        except Exception as e:
            logger.warn("Problem getting 'use-suricatasc' value from manifest: %s" % e)

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

    # get dumps from buffers
    getBufferDumps = False
    try:
        getBufferDumps = manifest_data[0]['get-buffer-dumps']
    except Exception:
        getBufferDumps = False

    # Zeek JSON logging
    JOB_ZEEK_JSON = False
    try:
        JOB_ZEEK_JSON = manifest_data[0]['zeek-json-logs']
    except Exception:
        JOB_ZEEK_JSON = False

    # make a directory for engine to use for alert, perf, and other sundry logs
    IDS_LOG_DIRECTORY = '%s/raw_ids_logs' % JOB_DIRECTORY
    if os.path.isdir(IDS_LOG_DIRECTORY):
        shutil.rmtree(IDS_LOG_DIRECTORY)
    os.makedirs(IDS_LOG_DIRECTORY)
    # not secure
    os.system("chmod -R 777 %s" % IDS_LOG_DIRECTORY)

    # for Snort, copy over some config files to JOB_DIRECTORY in case config references
    #  relative path to them.  These files should be in /etc/snort for the Docker Dalton
    #  Agents.
    cdir = "/etc/snort"
    if os.path.isdir(cdir):
        file_list = ["classification.config", "file_magic.conf", "gen-msg.map", "reference.config", "threshold.conf", "unicode.map"]
        for file in file_list:
            if os.path.isfile(os.path.join(cdir, file)):
                shutil.copyfile(os.path.join(cdir, file), os.path.join(JOB_DIRECTORY, file))

    # pcaps and config should be in manifest
    IDS_CONFIG_FILE = None
    if not SENSOR_ENGINE.startswith('zeek'):
        try:
            IDS_CONFIG_FILE = os.path.join(JOB_DIRECTORY, os.path.basename(manifest_data[0]['engine-conf']))
        except Exception:
            print_error("Could not extract engine configuration file from job.")

    try:
        PCAP_FILES = [os.path.join(JOB_DIRECTORY, PCAP_DIR, os.path.basename(cap)) for cap in manifest_data[0]['pcaps']]
        for pcap_file in PCAP_FILES:
            # move pcaps to their own directory (PCAP_DIR) since at this point they are in the JOB_DIRECTORY; can
            # be easier for the engine to process when there are multiple pcaps
            (base, name) = os.path.split(os.path.split(pcap_file)[0])
            shutil.move(os.path.join(os.path.dirname(os.path.dirname(pcap_file)), os.path.basename(pcap_file)), pcap_file)
    except Exception as e:
        print_error("Could not determine pcap files in job.")
        logger.debug("Problem moving pcaps to directory '%s': %s" % (os.path.join(JOB_DIRECTORY, PCAP_DIR), e))


    # parse job dir for configs and pcaps
    logger.debug("Parsing job directory: %s" % JOB_DIRECTORY)
    for file in glob.glob(os.path.join(JOB_DIRECTORY, "*")):
        if not os.path.isfile(file):
            continue
        if os.path.splitext(file)[1] == '.rules':
            IDS_RULES_FILES.append(file)

    # input validation (sort of)
    if not PCAP_FILES:
        print_error("No pcap files found")
    if not IDS_RULES_FILES and not SENSOR_ENGINE.startswith('zeek'):
        print_error("No rules files found")
    if not JOB_ID:
        print_error("job id not defined")

    if SENSOR_ENGINE.startswith('snort'):
        snort_conf_fh = open(IDS_CONFIG_FILE, "a")

        # include rules in config file
        for rules_file in IDS_RULES_FILES:
            snort_conf_fh.write("\ninclude %s\n" % rules_file)

        # set these output filenames explicitly so there is no guess where/what they are
        # NOTE: when MULTIPLE "output unified2:" directives are defined, Snort will
        #  write to both but only writes ExtraData records to one of them -- the last
        #  one defined. (The 'extra_data_config' (void pointer) variable used to log
        #  ExtraData is a global variable and thus only points to one config and thus
        #  one log file.).  This one is defined last so we get ExtraData which we want.
        snort_conf_fh.write("\noutput alert_full: alert-full_dalton-agent\n")
        snort_conf_fh.write("\noutput unified2: filename unified2.dalton.alert\n")

        snort_conf_fh.close()

    if SENSOR_ENGINE.startswith('suri'):
        # config/YAML should already be built on the controller
        suri_yaml_fh = open(IDS_CONFIG_FILE, "a")
        suri_yaml_fh.write("\n")
        # set default-rule-path; this is stripped out when the controller built
        # the job with the expectation that it be added here.
        print_debug("adding default-rule-path to yaml:\n%s" % '\n'.join(IDS_RULES_FILES))
        suri_yaml_fh.write("default-rule-path: %s\n" % JOB_DIRECTORY)
        suri_yaml_fh.close()
        # reading multiple pcaps added in Suricata 4.1
        if len(PCAP_FILES) > 1 and LooseVersion("4.1") > LooseVersion(SENSOR_ENGINE_VERSION_ORIG):
            print_error("Multiple pcap files were submitted to the Dalton Agent for a Suricata job.\n\nSuricata can only read a single pcap file so multiple pcaps submitted to the Dalton Controller should have been combined by the Controller when packaging the job.\n\nIf you see this, something went wrong on the Controller or you are doing something untoward.")

    if SENSOR_ENGINE.startswith('snort'):
        # this section applies only to Snort sensors
        # Snort uses DAQ dump and pcap read mode
        run_snort()

        # process snort alerts
        process_snort_alerts()

    elif SENSOR_ENGINE.startswith('suri'):
        # this section for Suricata agents
        if getFastPattern:
            generate_fast_pattern()
        # cannot get rule profiling or keyword profiling when using Socket Control
        if trackPerformance and USE_SURICATA_SOCKET_CONTROL:
            msg = "'Rule profiling' enabled, disabling Suricata Socket control."
            logger.warn(msg)
            print_debug(msg)
            USE_SURICATA_SOCKET_CONTROL = False
        # run the Suricata job
        if USE_SURICATA_SOCKET_CONTROL:
            run_suricata_sc()
        else:
            run_suricata()
        # populate the alerts (fast.log)
        process_suri_alerts()
        process_eve_log()

    elif SENSOR_ENGINE.startswith('zeek'):
        # this section applies only to Zeek sensors
        run_zeek(JOB_ZEEK_JSON)

        # process zeek alerts
        zeek_other_logs = process_zeek_logs()

    # the rest of this can apply to Snort and Suricata

    # other logs to return from the job; sensor specific
    other_logs = {}
    if SENSOR_ENGINE.startswith('suri'):
        # always return Engine and Packet Stats for Suri
        other_logs['Engine Stats'] = 'dalton-stats.log'
        other_logs['Packet Stats'] = 'dalton-packet_stats.log'
        if getOtherLogs:
            other_logs['Alert Debug'] = 'dalton-alert_debug.log'
            other_logs['HTTP Log'] = 'dalton-http.log'
            other_logs['TLS Log'] = 'dalton-tls.log'
            other_logs['DNS Log'] = 'dalton-dns.log'
        if getFastPattern:
            other_logs['Fast Pattern'] = 'rules_fast_pattern.txt'
        if trackPerformance:
            other_logs['Keyword Perf'] = 'dalton-keyword_perf.log'
        if getBufferDumps:
            other_logs['HTTP Buffers'] = 'dalton-http-buffers.log'
            other_logs['DNS Buffers'] = 'dalton-dns-buffers.log'
            other_logs['TLS Buffers'] = 'dalton-tls-buffers.log'
    # elif ... can add processing of logs from other engines here
    elif SENSOR_ENGINE.startswith('snort'):
        if getBufferDumps:
            other_logs['Buffer Dump'] = 'dalton-buffers.log'
    elif SENSOR_ENGINE.startswith('zeek'):
            other_logs = zeek_other_logs
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

    # Populate JOB_IDS_LOG accordingly for Suricata socket control
    if USE_SURICATA_SOCKET_CONTROL:
        with open(JOB_IDS_LOG, 'w') as fhout:
            if (not SCONTROL.suricata_is_running) and SCONTROL.log_offset == 0:
                # this means suri Errored at startup; pass here and just
                # the whole output file will be included later, otherwise
                # there will be duplicate output in the returned log
                pass
            else:
                # include initial suricata startup output
                fhout.write(f"{SCONTROL.suri_startup_log}\n-----\n\n")
            with open(suricata_logging_outputs_file, 'r') as fh:
                # include relevant part of suricata log from this job
                fh.seek(SCONTROL.log_offset, 0)
                fhout.write(fh.read())
                SCONTROL.log_offset = fh.tell()

    # check IDS output for error messages not identified and/or
    # handled elsewhere. Applies to Suri and Snort for now
    # calling this last so that everything else is populated
    # and can be sent back even though there could be an error
    check_for_errors(SENSOR_ENGINE)

    # check the pcaps to make sure incomplete, truncated, etc. pcaps weren't submitted.
    check_pcaps()

#################################################

# init class to use for suricata socket control
if USE_SURICATA_SOCKET_CONTROL:
    SCONTROL = SocketController(SURICATA_SOCKET_NAME)

# USE_SURICATA_SOCKET_CONTROL can get changed in submit_job(); save it
# so it can be reset between jobs.
USE_SURICATA_SOCKET_CONTROL_DEFAULT = USE_SURICATA_SOCKET_CONTROL

# agent part: send files via json, clean up files
while True:
    USE_SURICATA_SOCKET_CONTROL = USE_SURICATA_SOCKET_CONTROL_DEFAULT
    try:
        job = request_job()
        if (job != None):
            start_time = int(time.time())
            JOB_ID = job['id']
            logger.info("Job %s accepted by %s" % (JOB_ID, SENSOR_UID))
            send_update("Job %s Accepted by %s" % (JOB_ID, SENSOR_UID), JOB_ID)
            zf_path = request_zip(JOB_ID)
            logger.debug("Downloaded zip for %s successfully. Extracting file %s" % (JOB_ID, zf_path))
            send_update("Downloaded zip for %s successfully; extracting..." % JOB_ID, JOB_ID)
            # JOB_DEBUG_LOG not defined yet so can't call print_debug() here
            #print_debug("Extracting zip file for job id %s" % JOB_ID)
            JOB_DIRECTORY = "%s/%s_%s" % (STORAGE_PATH, JOB_ID, datetime.datetime.now().strftime("%b-%d-%Y_%H-%M-%S"))
            os.makedirs(os.path.join(JOB_DIRECTORY, PCAP_DIR))
            zf = zipfile.ZipFile(zf_path, 'r')
            filenames = zf.namelist()
            for filename in filenames:
                logger.debug("extracting file, %s" % filename)
                fh = open("%s/%s" % (JOB_DIRECTORY, filename), "wb")
                fh.write(zf.read(filename))
                fh.close()
            zf.close()
            logger.debug("Done extracting zipped files.")

            # submit the job!
            try:
                logger.info("Job %s running" % JOB_ID)
                submit_job(JOB_ID, JOB_DIRECTORY)
            except DaltonError as e:
                # dalton errors should already be written to JOB_ERROR_LOG and sent back
                logger.error("DaltonError caught:\n%s" % e)
                logger.debug("%s" % traceback.format_exc())
            except Exception as e:
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
                logger.error("Non DaltonError Exception caught:\n%s" % e)
                logger.debug("%s" % traceback.format_exc())

            TOTAL_PROCESSING_TIME = int(int(time.time())-start_time)
            print_debug("Total Processing Time (includes job download time): %d seconds" % TOTAL_PROCESSING_TIME)

            # send results back to server
            logger.info("Job %s done processing, sending back results" % JOB_ID)
            status = send_results()

            # clean up
            # remove zip file
            os.unlink(zf_path)
            # remove job directory and contained files
            if not KEEP_JOB_FILES:
                shutil.rmtree(JOB_DIRECTORY)
            logger.info("Job %s complete" % JOB_ID)
            JOB_ID = None
        else:
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Keyboard Interrupt caught, exiting....")
        try:
            if USE_SURICATA_SOCKET_CONTROL:
                SCONTROL.connect()
                SCONTROL.shutdown()
                SCONTROL.close()
        except:
            pass
        sys.exit(0)
    except DaltonError as e:
        logger.debug("DaltonError caught (in while True loop):\n%s" % e)
    except Exception as e:
        logger.debug("General Dalton Agent exception caught. Error:\n%s\n%s" % (e, traceback.format_exc()))
        if JOB_ID:
            # unexpected error happened on agent when trying to process a job but there may not be job data so compile an empty response with the exception error message and try to send it
            logger.warn("Possible communication error processing jobid %s.  Attempting to send error message to controller." % JOB_ID)
            try:
                error_post_results(e)
                logger.info("Successfully sent error message to controller for jobid %s" % JOB_ID)
            except Exception as e:
                logger.error("Could not communicate with controller to send error info for jobid %s; is the Dalton Controller accepting network communications? Error:\n%s" % (JOB_ID, e))
                time.sleep(ERROR_SLEEP_TIME)
        else:
            logger.error("Agent Error -- Is the Dalton Controller accepting network communications?")
            sys.stdout.flush()
            time.sleep(ERROR_SLEEP_TIME)
#    finally:
#        try:
#            if USE_SURICATA_SOCKET_CONTROL:
#                SCONTROL.connect()
#                SCONTROL.shutdown()
#                SCONTROL.close()
#        except:
#            pass
