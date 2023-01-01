#!/usr/local/bin/python
"""
Dalton - a UI and management tool for submitting and viewing IDS jobs
"""
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

# app imports
from flask import Blueprint, render_template, request, Response, redirect, url_for
#from flask_login import current_user
import hashlib
import os
import glob
import re
import redis
import datetime
import time
import json
import zipfile
import tarfile
import gzip
import bz2
import sys
import shutil
from distutils.version import LooseVersion
import configparser
import logging
from logging.handlers import RotatingFileHandler
import subprocess
from ruamel import yaml
import base64
import traceback
import subprocess
import random
from threading import Thread
import tempfile
import copy

# setup the dalton blueprint
dalton_blueprint = Blueprint('dalton_blueprint', __name__, template_folder='templates/dalton/')

# logging
file_handler = RotatingFileHandler('/var/log/dalton.log', 'a', 1 * 1024 * 1024, 10)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
logger = logging.getLogger("dalton")
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

logger.info("Logging started")

try:
    dalton_config_filename = 'dalton.conf'
    dalton_config = configparser.SafeConfigParser()
    dalton_config.read(dalton_config_filename)
    TEMP_STORAGE_PATH = dalton_config.get('dalton', 'temp_path')
    RULESET_STORAGE_PATH = dalton_config.get('dalton', 'ruleset_path')
    JOB_STORAGE_PATH = dalton_config.get('dalton', 'job_path')
    CONF_STORAGE_PATH = dalton_config.get('dalton', 'engine_conf_path')
    REDIS_EXPIRE = (dalton_config.getint('dalton', 'redis_expire') * 60)
    SHARE_EXPIRE = (dalton_config.getint('dalton', 'share_expire') * 60)
    TEAPOT_REDIS_EXPIRE = (dalton_config.getint('dalton', 'teapot_redis_expire') * 60)
    JOB_RUN_TIMEOUT = dalton_config.getint('dalton', 'job_run_timeout')
    AGENT_PURGE_TIME = dalton_config.getint('dalton', 'agent_purge_time')
    REDIS_HOST = dalton_config.get('dalton', 'redis_host')
    API_KEYS = dalton_config.get('dalton', 'api_keys')
    MERGECAP_BINARY = dalton_config.get('dalton', 'mergecap_binary')
    U2_ANALYZER = dalton_config.get('dalton', 'u2_analyzer')
    RULECAT_SCRIPT = dalton_config.get('dalton', 'rulecat_script')
    MAX_PCAP_FILES = dalton_config.getint('dalton', 'max_pcap_files')
    DEBUG = dalton_config.getboolean('dalton', 'debug')

    #options for flowsynth
    FS_BIN_PATH = dalton_config.get('flowsynth-web', 'bin_path')    #Path to the flowsynth application
    FS_PCAP_PATH = dalton_config.get('flowsynth-web', 'pcap_path')  #Path to temporarily store PCAPs

except Exception as e:
    logger.critical("Problem parsing config file '%s': %s" % (dalton_config_filename, e))

if DEBUG or ("CONTROLLER_DEBUG" in os.environ and int(os.getenv("CONTROLLER_DEBUG"))):
    logger.setLevel(logging.DEBUG)
    DEBUG = True
    logger.debug("DEBUG logging enabled")

if not MERGECAP_BINARY or not os.path.exists(MERGECAP_BINARY):
    logger.error("mergecap binary '%s'  not found.  Suricata jobs cannot contain more than one pcap." % MERGECAP_BINARY)
    MERGECAP_BINARY = None

#connect to the datastore
try:
    # redis values are retured as byte objects by default. Automatically
    # decode them to utf-8.
    r = redis.Redis(REDIS_HOST, charset="utf-8", decode_responses=True)
except Exception as e:
    logger.critical("Problem connecting to Redis host '%s': %s" % (REDIS_HOST, e))

# if there are no rules, use idstools rulecat to download a set for Suri and Snort
# if rulecat fails (eaten by proxy), empty rules file(s) may be created
# TODO: change this to use suricata-update?
for engine in ['suricata', 'snort']:
    ruleset_dir = os.path.join(RULESET_STORAGE_PATH, engine)
    rules = [f for f in os.listdir(ruleset_dir) if (os.path.isfile(os.path.join(ruleset_dir, f)) and f.endswith(".rules"))]
    if len(rules) == 0:
        filename = "ET-%s-all-%s.rules" % (datetime.datetime.utcnow().strftime("%Y%m%d"), engine)
        logger.info("No rulesets for %s found. Downloading the latest ET set as '%s'" % (engine, filename))
        if engine == "suricata":
            url = "https://rules.emergingthreats.net/open/suricata-4.0/emerging.rules.tar.gz"
        if engine == "snort":
            url = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz"
        command = "%s --url %s --merged %s" % (RULECAT_SCRIPT, url, os.path.join(ruleset_dir, filename))
        try:
            subprocess.call(command, stdin=None, stdout=None, stderr=None, shell=True)
        except Exception as e:
            logger.info("Unable to download ruleset for %s" % engine)
            logger.debug("Exception: %s" % e)

# check for sane timeout values
if REDIS_EXPIRE <= 0:
    logger.critical("redis_expire value of %d minutes is invalid.  Expect problems." % dalton_config.getint('dalton', 'redis_expire'))
if TEAPOT_REDIS_EXPIRE <= 0:
    logger.critical("teapot_redis_expire value of %d minutes is invalid.  Expect problems." % dalton_config.getint('dalton', 'teapot_redis_expire'))
if AGENT_PURGE_TIME <= 1:
    logger.critical("agent_purge_time value of %d seconds is invalid.  Expect problems." % AGENT_PURGE_TIME)
if JOB_RUN_TIMEOUT <= 4:
    logger.critical("job_run_time value of %d seconds is invalid.  Expect problems." % JOB_RUN_TIMEOUT)
if TEAPOT_REDIS_EXPIRE > REDIS_EXPIRE:
    logger.warn("teapot_redis_expire value %d greater than redis_expire value %d. This is not recommended and may result in teapot jobs being deleted from disk before they expire in Redis." % (TEAPOT_REDIS_EXPIRE, REDIS_EXPIRE))

# other checks
if MAX_PCAP_FILES < 1:
    default_max = 8
    logger.warn("max_pcap_files value of '%d' invalid.  Using '%d'" % (MAX_PCAP_FILES, default_max))
    MAX_PCAP_FILES = default_max

#global values used by Flask
TRAP_BAD_REQUEST_KEY_ERRORS = True

#status codes
STAT_CODE_INVALID = -1
STAT_CODE_QUEUED = 0
STAT_CODE_RUNNING = 1
STAT_CODE_DONE = 2
STAT_CODE_INTERRUPTED = 3
STAT_CODE_TIMEOUT = 4

# engine technologies supported; used for validation (sometimes)
supported_engines = ['suricata', 'snort', 'zeek']

logger.info("Dalton Started.")

""" returns normalized path; used to help prevent directory traversal """
def clean_path(mypath):
    return os.path.normpath('/' + mypath).lstrip('/')


def prefix_strip(mystring, prefixes=["rust_"]):
    """ strip passed in prefixes from the beginning of passed in string and return it
    """
    if not isinstance(prefixes, list):
        prefixes = [prefixes]
    for prefix in prefixes:
        if mystring.startswith(prefix):
            return mystring[len(prefix):]
    return mystring

def get_engine_and_version(sensor_tech):
    """ returns list with engine ("suricata" or "snort") as first element, and
    version (e.g. "5.0.1", "2.9.9.0" as second element. Strips out prefix (e.g. "rust_")
    and ignores custom config (if present).  Example passed in 'sensor_tech' values:
        suricata/5.0.1
        suricata/rust_4.1.5
        suricata/4.0.7/mycustomconf
        suricata/rust_4.1.5/mycustomconf
        snort/2.9.9.0
    """
    try:
        engine = sensor_tech.split('/')[0]
        version = prefix_strip(sensor_tech.split('/')[1])
        return (engine, version)
    except Exception as e:
        logger.error(f"Unable to process value '{sensor_tech}' in get_engine_and_version(): {e}")
        return (None, None)

def delete_temp_files(job_id):
    """ deletes temp files for given job ID"""
    global TEMP_STORAGE_PATH
    if os.path.exists(TEMP_STORAGE_PATH):
        for file in glob.glob(os.path.join(TEMP_STORAGE_PATH, "%s*" % job_id)):
            if os.path.isfile(file):
                os.unlink(file)
    if os.path.exists(os.path.join(TEMP_STORAGE_PATH, job_id)):
        shutil.rmtree(os.path.join(TEMP_STORAGE_PATH, job_id))

def verify_temp_storage_path():
    """verify and create if necessary the temp location where we will store files (PCAPs, configs, etc.)
       when build a job zip file
    """
    global TEMP_STORAGE_PATH
    if not os.path.exists(TEMP_STORAGE_PATH):
        os.makedirs(TEMP_STORAGE_PATH)
    return True

@dalton_blueprint.route('/dalton/controller_api/get-prod-rulesets/<engine>', methods=['GET'])
def api_get_prod_rulesets(engine):
    global supported_engines
    if engine is None or engine == '' or engine not in supported_engines:
        return Response("Invalid 'engine' supplied.  Must be one of %s.\nExample URI:\n\n/dalton/controller_api/get-prod-rulesets/suricata" % supported_engines, 
                        status=400, mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})
    # return json
    ruleset_list = []
    # this is a 2D array with filename and full path for each rules file
    #  but this function only returns a 1D array with full paths
    current_rulesets = get_rulesets(engine)
    for ruleset in current_rulesets:
        if len(ruleset) > 1:
            ruleset_list.append(ruleset[1])

    json_response = {'prod-rulesets': ruleset_list}
    return Response(json.dumps(json_response), status=200, mimetype='application/json', headers = {'X-Dalton-Webapp':'OK'})

def get_rulesets(engine=''):
    """ return a list of locally stored ruleset for jobs to use """
    global RULESET_STORAGE_PATH
    ruleset_list = []
    logger.debug("in get_rulesets(engine=%s)" % engine)
    # engine var should already be validated but just in case
    if not re.match(r"^[a-zA-Z0-9\_\-\.]*$", engine):
        logger.error("Invalid engine value '%s' in get_rulesets()" % engine)
        return ruleset_list
    ruleset_dir = os.path.join(RULESET_STORAGE_PATH, clean_path(engine))
    if not os.path.isdir(ruleset_dir):
        logger.error("Could not find ruleset directory '%s'" % ruleset_dir)
        return ruleset_list
    file_list = os.listdir(ruleset_dir)
    # do we want to descend into directories?
    for file in file_list:
        if not os.path.isfile(os.path.join(ruleset_dir, file)):
            continue
        if  os.path.splitext(file)[1] == '.rules':
            # just add file (base) for now so we can sort; build 2D list on return
            ruleset_list.append(os.path.basename(file))
    #sort
    ruleset_list.sort(reverse=True)

    # return 2D array with base and full path
    return [[file, os.path.join(ruleset_dir, file)] for file in ruleset_list]

def set_job_status_msg(jobid, msg):
    """set a job's status message """
    global r
    r.set("%s-status" % jobid, msg)
    # status keys do not expire if/when they are queued
    if msg != "Queued":
        if r.get("%s-teapotjob" % jobid):
            r.expire("%s-status" % jobid, TEAPOT_REDIS_EXPIRE)
        else:
            r.expire("%s-status" % jobid, REDIS_EXPIRE)

def get_job_status_msg(jobid):
    """returns a job's status message"""
    return r.get("%s-status" % jobid)


def set_job_status(jobid, status):
    """set's a job status code"""
    global r
    r.set("%s-statcode" % jobid, status)
    # statcode keys do not expire if/when they are queued
    if status != STAT_CODE_QUEUED:
        if r.get("%s-teapotjob" % jobid):
            r.expire("%s-statcode" % jobid, TEAPOT_REDIS_EXPIRE)
        else:
            r.expire("%s-statcode" % jobid, REDIS_EXPIRE)

def get_job_status(jobid):
    """return a job's status code"""
    return r.get("%s-statcode" % jobid)

def get_alert_count(jobid):
    if r.exists(f"{jobid}-alert"):
        return r.get(f"{jobid}-alert").count('[**]') // 2
    else:
        return None

def set_keys_timeout(jobid):
    """set timeout of REDIS_EXPIRE seconds on keys that (should) be set when job results are posted"""
    EXPIRE_VALUE = REDIS_EXPIRE
    if r.get("%s-teapotjob" % jobid):
        EXPIRE_VALUE = TEAPOT_REDIS_EXPIRE
    try:
        r.expire("%s-ids" % jobid, EXPIRE_VALUE)
        r.expire("%s-perf" % jobid, EXPIRE_VALUE)
        r.expire("%s-alert" % jobid, EXPIRE_VALUE)
        r.expire("%s-error" % jobid, EXPIRE_VALUE)
        r.expire("%s-debug" % jobid, EXPIRE_VALUE)
        r.expire("%s-time" % jobid, EXPIRE_VALUE)
        r.expire("%s-alert_detailed" % jobid, EXPIRE_VALUE)
        r.expire("%s-other_logs" % jobid, EXPIRE_VALUE)
        r.expire("%s-eve" % jobid, EXPIRE_VALUE)
        r.expire("%s-teapotjob" % jobid, EXPIRE_VALUE)
        r.expire("%s-zeek_json" % jobid, EXPIRE_VALUE)
    except:
        pass

def expire_all_keys(jid):
    """expires (deletes) all keys for a give job ID"""
    # using the redis keys function ('r.keys("%s-*" % jid)') searches thru all keys which is not
    #   efficient for large key sets so we are deleting each one individually
    global r
    logger.debug("Dalton calling expire_all_keys() on job %s" % jid)
    keys_to_delete = ["ids", "perf", "alert", "alert_detailed", "other_logs", "eve", "error", "debug", "time", "statcode", "status", "start_time", "user", "tech", "submission_time", "teapotjob", "zeek_json"]
    try:
        for cur_key in keys_to_delete:
            r.delete("%s-%s" % (jid, cur_key))
    except:
        pass

def check_for_timeout(jobid):
    """checks to see if a job has been running more than JOB_RUN_TIMEOUT seconds and sets it to STAT_CODE_TIMEOUT and sets keys to expire"""
    global r
    try:
        start_time = int(r.get("%s-start_time" % jobid))
    except:
        start_time = int(time.time()) - (JOB_RUN_TIMEOUT + 1)
    #logger.debug("Dalton in check_for_timeout(): job %s start time: %d" % (jobid, start_time))
    if not start_time or ((int(time.time()) - start_time) > JOB_RUN_TIMEOUT):
        if int(get_job_status(jobid)) == STAT_CODE_RUNNING:
            logger.info("Dalton in check_for_timeout(): job %s timed out.  Start time: %d, now: %d" % (jobid, start_time, int(time.time())))
            set_job_status(jobid, STAT_CODE_TIMEOUT)
            set_job_status_msg(jobid, "Job %s has timed out, please try submitting the job again." % jobid)
            set_keys_timeout(jobid)
            return True
        else:
            return False
    else:
        return False


@dalton_blueprint.route('/dalton/controller_api/delete-old-job-files', methods=['GET'])
def delete_old_job_files():
    """Deletes job files on disk if modification time exceeds expire time(s)"""
    global REDIS_EXPIRE, TEAPOT_REDIS_EXPIRE, JOB_STORAGE_PATH, logger
    total_deleted = 0

    # this coded but not enabled since there isn't any authentication and I don't think 
    #  anyone should be able to delete jobs older than any arbitrary number of minutes
    if request:
        mmin = request.args.get('mmin')
        teapot_mmin = request.args.get('teapot_mmin')
        if mmin is not None:
            logger.warn("Passing a mmin value to delete_old_job_files() is currently not enabled.  Using %d seconds for regular jobs." % REDIS_EXPIRE)
        if teapot_mmin is not None:
            logger.warn("Passing a teapot_mmin value to delete_old_job_files() is currently not enabled.  Using %d seconds for teapot jobs." % TEAPOT_REDIS_EXPIRE)

    # these values represent number of minutes
    job_mmin = REDIS_EXPIRE
    teapot_mmin = TEAPOT_REDIS_EXPIRE

    if os.path.exists(JOB_STORAGE_PATH):
        now = time.time()
        # assumption is REDIS_EXPIRE >= TEAPOT_REDIS_EXPIRE
        for file in glob.glob(os.path.join(JOB_STORAGE_PATH, "*.zip")):
            if os.path.isfile(file):
                mtime = os.path.getmtime(file)
                if (now-mtime) > REDIS_EXPIRE:
                    logger.debug("Deleting job file '%s'. mtime %s; now %s; diff %d seconds; expire threshold %d seconds" % (os.path.basename(file), now, mtime, (now-mtime), REDIS_EXPIRE))
                    os.unlink(file)
                    total_deleted += 1
        for file in glob.glob(os.path.join(JOB_STORAGE_PATH, "teapot_*.zip")):
            if os.path.isfile(file):
                mtime = os.path.getmtime(file)
                if (now-mtime) > TEAPOT_REDIS_EXPIRE:
                    logger.debug("Deleting teapot job file '%s'. mtime %s; now %s; diff %d seconds; expire threshold %d seconds" % (os.path.basename(file), now, mtime, (now-mtime), TEAPOT_REDIS_EXPIRE))
                    os.unlink(file)
                    total_deleted += 1
    if total_deleted > 0:
        logger.info("Deleted %d job file(s) from disk." % total_deleted)
    # returning a string so Flask can render it; calling functions that use the
    #  return value need to cast it back to int if they wish to use it as an int
    return str(total_deleted)

@dalton_blueprint.route('/')
def index():
    logger.debug("ENVIRON:\n%s" % request.environ)
    # make sure redirect is set to use http or https as appropriate
    rurl = url_for('dalton_blueprint.page_index', _external=True)
    if rurl.startswith('http'):
        if "HTTP_X_FORWARDED_PROTO" in request.environ:
            # if original request was https, make sure redirect uses https
            rurl = rurl.replace('http', request.environ['HTTP_X_FORWARDED_PROTO'])
        else:
            logger.warn("Could not find request.environ['HTTP_X_FORWARDED_PROTO']. Make sure the web server (proxy) is configured to send it.")
    else:
        # this shouldn't be the case with '_external=True' passed to url_for()
        logger.warn("URL does not start with 'http': %s" % rurl)
    return redirect(rurl)

@dalton_blueprint.route('/dalton')
@dalton_blueprint.route('/dalton/')
#@login_required()
def page_index():
    """the default homepage for Dalton"""
    return render_template('/dalton/index.html', page='')


# 'sensor' value includes forward slashes so this isn't a RESTful endpoint
# and 'sensor' value must be passed as a GET parameter
@dalton_blueprint.route('/dalton/controller_api/request_engine_conf', methods=['GET'])
#@auth_required()
def api_get_engine_conf_file():
    global supported_engines
    try:
        sensor = request.args['sensor']
    except Exception as e:
        sensor = None
    if not sensor or len(sensor) == 0:
        return Response("Invalid 'sensor' supplied.",
                        status=400, mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})
    return Response(get_engine_conf_file(sensor), status=200, mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})

def get_engine_conf_file(sensor):
    """ return the corresponding configuration file for passed in sensor (engine and version)
    """
    # User's browser should be making request to dynamically update 'coverage' submission page
    # Also called by API handler
    try:
        conf_file = None
        vars_file = None
        custom_config = None
        try:
            # if custom config used
            # 'sensor' varible format example: suricata/5.0.0/mycustomfilename
            (engine, version, custom_config) = sensor.split('/', 2)
            epath = os.path.join(CONF_STORAGE_PATH, clean_path(engine))
            if os.path.isfile(os.path.join(epath, "%s" % custom_config)):
                conf_file = "%s" % custom_config
            elif os.path.isfile(os.path.join(epath, "%s.yaml" % custom_config)):
                conf_file = "%s.yaml" % custom_config
            elif os.path.isfile(os.path.join(epath, "%s.yml" % custom_config)):
                conf_file = "%s.yml" % custom_config
            elif os.path.isfile(os.path.join(epath, "%s.conf" % custom_config)):
                conf_file = "%s.conf" % custom_config
            if conf_file:
                conf_file = (os.path.join(epath, clean_path(conf_file)))
                logger.debug(f"Found custom config file: '{conf_file}'")
            else:
                logger.error(f"Unable to find custom config file '{custom_config}'")
                engine_config = f"# Unable to find custom config file '{custom_config}'"
                return engine_config
        except ValueError:
            # no custom config
            (engine, version) = sensor.split('/', 1)
            version = prefix_strip(version, prefixes="rust_")
            sensor2 = f"{engine}-{version}"
            epath = os.path.join(CONF_STORAGE_PATH, clean_path(engine))

            filelist = [f for f in os.listdir(epath) if os.path.isfile(os.path.join(epath, f))]
            # assumes an extension (e.g. '.yaml', '.conf') on engine config files
            # if exact match, just use that instead of relying on LooseVersion
            files = [f for f in filelist if os.path.splitext(f)[0] == sensor2]
            if len(files) == 0:
                files = [f for f in filelist if LooseVersion(os.path.splitext(f)[0]) <= LooseVersion(sensor2)]
            if len(files) > 0:
                files.sort(key=lambda v:LooseVersion(os.path.splitext(v)[0]), reverse=True)
                conf_file = os.path.join(epath, files[0])
            logger.debug("in get_engine_conf_file(): passed sensor value: '%s', conf file used: '%s'", sensor, os.path.basename(conf_file))

        engine_config = ''

        if conf_file:
            # open, read, return
            # Unix newline is \n but for display on web page, \r\n is desired in some
            # browsers/OSes.  Note: currently not converted back on job submit.
            with open(conf_file, 'r') as fh:
                # want to parse each line so put it into a list
                contents = fh.readlines()
            logger.debug("Loading config file %s", conf_file)

            engine_config = '\r\n'.join([x.rstrip('\r\n') for x in contents])
        else:
            logger.warn("No suitable configuration file found for sensor '%s'.", sensor)
            engine_config = f"# No suitable configuration file found for sensor '{sensor}'."
        return engine_config

    except Exception as e:
        logger.error("Problem getting configuration file for sensor '%s'.  Error: %s\n%s", sensor, e, traceback.format_exc())
        engine_config = f"# Exception getting configuration file for sensor '{sensor}'."
        if DEBUG:
            engine_config += f"  Error: {e}\r\n{traceback.format_exc()}"
        return engine_config

@dalton_blueprint.route('/dalton/sensor_api/update/', methods=['POST'])
#@auth_required('write')
# status update from Dalton Agent
def sensor_update():
    """ a sensor has submitted an api update"""
    global r
    global STAT_CODE_DONE

    uid = request.form.get('uid')
    msg = request.form.get('msg')
    job = request.form.get('job')

    if int(get_job_status(job)) != STAT_CODE_DONE:
        set_job_status_msg(job, msg)

    logger.debug("Dalton Agent %s sent update for job %s; msg: %s" % (uid, job, msg))

    return "OK"


@dalton_blueprint.route('/dalton/sensor_api/request_job', methods=['GET'])
#@auth_required('read')
def sensor_request_job():
    """Sensor API. Called when a sensor wants a new job"""
    # job request from Dalton Agent
    global r
    global STAT_CODE_RUNNING

    try:
        SENSOR_UID = request.args['SENSOR_UID']
    except Exception as e:
        SENSOR_UID = 'unknown'

    SENSOR_IP = request.remote_addr

    try:
        AGENT_VERSION = request.args['AGENT_VERSION']
    except Exception as e:
        AGENT_VERSION = 'unknown'

    try:
        SENSOR_ENGINE = request.args['SENSOR_ENGINE']
    except Exception as e:
        SENSOR_ENGINE = 'unknown'
    try:
        SENSOR_ENGINE_VERSION = request.args['SENSOR_ENGINE_VERSION']
    except Exception as e:
        SENSOR_ENGINE_VERSION = 'unknown'

    sensor_tech = f"{SENSOR_ENGINE}/{SENSOR_ENGINE_VERSION}"

    SENSOR_CONFIG = None
    if 'SENSOR_CONFIG' in request.args.keys():
        try:
            SENSOR_CONFIG = request.args['SENSOR_CONFIG']
        except Exception as e:
            SENSOR_CONFIG = None

    if SENSOR_CONFIG and len(SENSOR_CONFIG) > 0:
        sensor_tech += f"/{SENSOR_CONFIG}"

    # update check-in data; use md5 hash of SENSOR_UID.SENSOR_IP
    # note: sensor keys are expired by function clear_old_agents() which removes the sensor
    # when it has not checked in in <x> amount of time (expire time configurable via
    # 'agent_purge_time' parameter in dalton.conf).
    hash = hashlib.md5()
    hash.update(SENSOR_UID.encode('utf-8'))
    hash.update(SENSOR_IP.encode('utf-8'))
    SENSOR_HASH = hash.hexdigest()
    r.sadd("sensors", SENSOR_HASH)
    r.set(f"{SENSOR_HASH}-uid", SENSOR_UID)
    r.set(f"{SENSOR_HASH}-ip", SENSOR_IP)
    r.set(f"{SENSOR_HASH}-time", datetime.datetime.now().strftime("%b %d %H:%M:%S"))
    r.set(f"{SENSOR_HASH}-epoch", int(time.mktime(time.localtime())))
    r.set(f"{SENSOR_HASH}-tech", sensor_tech)
    r.set(f"{SENSOR_HASH}-agent_version", AGENT_VERSION)

    #grab a job! If it doesn't exist, return sleep.
    response = r.lpop(sensor_tech)
    if (response == None):
        return "sleep"
    else:
        respobj = json.loads(response)
        new_jobid = respobj['id']
        logger.info("Dalton Agent %s grabbed job %s for %s" % (SENSOR_UID, new_jobid, sensor_tech))
        # there is a key for each sensor which is ("%s-current_job" % SENSOR_HASH) and has
        #  the value of the current job id it is running.  This value is set when a job is
        #  requested and set to 'None' when the results are posted.  A sensor can only run
        #  one job at a time so if there is an exiting job when the sensor requests a new
        #  job then that means the sensor was interrupted while processing a job and could
        #  did not communicate back with the controller.
        existing_job = r.get("%s-current_job" % SENSOR_HASH)
        #logger.debug("Dalton in sensor_request_job(): job requested, sensor hash %s, new job: %s, existing job: %s" % (SENSOR_HASH, new_jobid, existing_job))
        if existing_job and existing_job != new_jobid:
            set_job_status(existing_job, STAT_CODE_INTERRUPTED)
            set_job_status_msg(existing_job, "Job %s was unexpectedly interrupted while running on the agent; please try submitting the job again." % existing_job)
            # these shouldn't be populated but set them to expire just in case to prevent redis memory build up
            set_keys_timeout(existing_job)
        r.set("%s-current_job" % SENSOR_HASH, new_jobid)
        EXPIRE_VALUE = REDIS_EXPIRE
        if r.get("%s-teapotjob" % new_jobid):
            EXPIRE_VALUE = TEAPOT_REDIS_EXPIRE
        r.expire("%s-current_job" % SENSOR_HASH, EXPIRE_VALUE)
        r.set("%s-start_time" % new_jobid, int(time.time()))
        r.expire("%s-start_time" % new_jobid, EXPIRE_VALUE)
        set_job_status(new_jobid,STAT_CODE_RUNNING)
        # if a user sees the "Running" message for more than a few dozen seconds (depending on
        #   the size of the pcap(s) and ruleset), then the job is hung on the agent or is going to
        #   timeout. Most likely the agent was killed or died during the job run.
        set_job_status_msg(new_jobid, "Running...")

        # set expire times for keys that are stored on server until job is requested
        r.expire("%s-submission_time" % new_jobid, EXPIRE_VALUE)
        r.expire("%s-user" % new_jobid, EXPIRE_VALUE)
        r.expire("%s-tech" % new_jobid, EXPIRE_VALUE)
        return response


@dalton_blueprint.route('/dalton/sensor_api/results/<jobid>', methods=['POST'])
#@auth_required('write')
def post_job_results(jobid):
    """ called by Dalton Agent sending job results """
    # no authentication or authorization so this is easily abused; anyone with jobid
    # can overwrite results if they submit first.
    global STAT_CODE_DONE, STAT_CODE_RUNNING, STAT_CODE_QUEUED, DALTON_URL, REDIS_EXPIRE, TEAPOT_REDIS_EXPIRE, TEMP_STORAGE_PATH
    global r

    # check and make sure job results haven't already been posted in order to prevent
    # abuse/overwriting.  This still isn't foolproof.
    if r.exists("%s-time" % jobid) and (int(get_job_status(jobid)) not in [STAT_CODE_RUNNING, STAT_CODE_QUEUED]):
        logger.error("Data for jobid %s already exists in database; not overwriting. Source IP: %s. job_status_code code: %d" % (jobid, request.remote_addr, int(get_job_status(jobid))))
         #typically this would go back to Agent who then ignores it
        return Response("Error: job results already exist.", mimetype='text/plain', headers = {'X-Dalton-Webapp':'Error'})

    jsons = request.form.get('json_data')
    result_obj = json.loads(jsons)

    set_job_status_msg(jobid, "Final Job Status: %s" % result_obj['status'])
    # get sensor hash and update ("%s-current_job" % SENSOR_HASH) with 'None'
    SENSOR_IP = request.remote_addr
    SENSOR_UID = 'unknown'
    try:
        SENSOR_UID = request.args['SENSOR_UID']
    except Exception as e:
        SENSOR_UID = 'unknown'
    hash = hashlib.md5()
    hash.update(SENSOR_UID.encode('utf-8'))
    hash.update(SENSOR_IP.encode('utf-8'))
    SENSOR_HASH = hash.hexdigest()
    r.set(f"{SENSOR_HASH}-current_job", None)
    r.expire(f"{SENSOR_HASH}-current_job", REDIS_EXPIRE)

    logger.info("Dalton Agent %s submitted results for job %s. Result: %s", SENSOR_UID, jobid, result_obj['status'])

    #save results to db
    if 'ids' in result_obj:
        ids = result_obj['ids']
    elif 'snort' in result_obj:
        ids = result_obj['snort']
    else:
        ids = ""
    if 'performance' in result_obj:
        perf = result_obj['performance']
    else:
        perf = ""
    if 'alert' in result_obj:
        alert = result_obj['alert']
    else:
        alert = ""
    if 'error' in result_obj:
        error = result_obj['error']
    else:
        error = ""
    if 'debug' in result_obj:
        debug = result_obj['debug']
    else:
        debug = ""
    if 'total_time' in result_obj:
        time = result_obj['total_time']
    else:
        time = ""
    # alert_detailed is base64 encoded unified2 binary data
    alert_detailed = ""
    if 'alert_detailed' in result_obj:
        try:
            # write to disk and pass to u2spewfoo.py; we could do
            #  myriad other things here like modify or import that
            #  code but this works and should be compatible and
            #  incorporate any future changes/improvements to the
            #  script
            u2_file = os.path.join(TEMP_STORAGE_PATH, "%s_unified2_%s" % (jobid, SENSOR_HASH))
            u2_fh = open(u2_file, "wb")
            u2_fh.write(base64.b64decode(result_obj['alert_detailed']))
            u2_fh.close()
            u2spewfoo_command = "%s %s" % (U2_ANALYZER, u2_file)
            logger.debug("Processing unified2 data with command: '%s'" % u2spewfoo_command)
            alert_detailed = subprocess.Popen(u2spewfoo_command, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.read()
            # delete u2 file
            os.unlink(u2_file)
        except Exception as e:
            logger.error("Problem parsing unified2 data from Agent.  Error: %s" % e)
            alert_detailed = ""
    else:
        alert_detailed = ""

    # other_logs only supported on Suricata for now
    if "other_logs" in result_obj:
        logger.debug("Accessing other_log data from agent POST...")
        other_logs = result_obj['other_logs']
    else:
        other_logs = ""

    # EVE is Suricata only
    if "eve" in result_obj:
        logger.debug("Accessing EVE data from agent POST...")
        eve = result_obj['eve']
    else:
        eve = ""

    # Use JSON logs for Zeek
    if "zeek_json" in result_obj:
        logger.debug("Accessing Zeek JSON data from agent POST...")
        zeek_json = result_obj['zeek_json']
    else:
        zeek_json = False

    logger.debug("Saving job data to redis...")
    r.set("%s-ids" % jobid, ids)
    r.set("%s-perf" % jobid, perf)
    r.set("%s-alert" % jobid, alert)
    r.set("%s-error" % jobid, error)
    r.set("%s-debug" % jobid, debug)
    r.set("%s-time" % jobid, time)
    r.set("%s-alert_detailed" % jobid, alert_detailed)
    r.set("%s-other_logs" % jobid, other_logs)
    r.set("%s-eve" % jobid, eve)
    r.set("%s-zeek_json" % jobid, zeek_json)
    set_keys_timeout(jobid)
    logger.debug("Done saving job data to redis.")

    if error:
        set_job_status_msg(jobid, '<div style="color:red">ERROR!</div> <a href="/dalton/job/%s">Click here for details</a>' % jobid)
    else:
        set_job_status_msg(jobid, '<a href="/dalton/job/%s">Click here to view your results</a>' % jobid)

    set_job_status(jobid, STAT_CODE_DONE)
    logger.debug("Returning from post_job_results()")
    return Response("OK", mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})

@dalton_blueprint.route('/dalton/controller_api/job_status/<jobid>', methods=['GET'])
#@login_required()
def get_ajax_job_status_msg(jobid):
    """return the job status msg (as a string)"""
    # user's browser requesting job status msg
    global STAT_CODE_RUNNING
    if not validate_jobid(jobid):
        return Response("Invalid Job ID: %s" % jobid, mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})
    stat_code = get_job_status(jobid)
    if stat_code:
        if int(stat_code) == STAT_CODE_RUNNING:
            check_for_timeout(jobid)
        r_status_msg = get_job_status_msg(jobid)
        if r_status_msg:
            return Response(r_status_msg, mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})
        else:
            return Response('Unknown', mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})
    else:
        return Response("Invalid Job ID: %s" % jobid, mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})

@dalton_blueprint.route('/dalton/controller_api/job_status_code/<jobid>', methods=['GET'])
#@login_required()
def get_ajax_job_status_code(jobid):
    """return the job status code (AS A STRING! -- you need to cast the return value as an int if you want to use it as an int)"""
    # user's browser requesting job status code
    if not validate_jobid(jobid):
        return "%d" % STAT_CODE_INVALID
    r_status_code = get_job_status(jobid)
    if not r_status_code:
        # invalid jobid
        return "%d" % STAT_CODE_INVALID
    else:
        if int(r_status_code) == STAT_CODE_RUNNING:
            check_for_timeout(jobid)
        return get_job_status(jobid)


@dalton_blueprint.route('/dalton/sensor_api/get_job/<id>', methods=['GET'])
#@auth_required('read')
def sensor_get_job(id):
    """user or agent requesting a job zip file"""
    # get the user (for logging)
    logger.debug("Dalton in sensor_get_job(): request for job zip file %s", id)
    if not validate_jobid(id):
        logger.error("Bad jobid given: '%s'. Possible hacking attempt.", id)
        return render_template('/dalton/error.html', jid=id, msg=[f"Bad jobid, invalid characters in: '{id}'"])
    path = f"{JOB_STORAGE_PATH}/{id}.zip"
    if os.path.exists(path):
        with open(path, 'rb') as fh:
            logger.debug(f"Dalton in sensor_get_job(): sending job zip file {id}")
            return Response(fh.read(),mimetype="application/zip", headers={"Content-Disposition":f"attachment;filename={id}.zip"})
    else:
        logger.error(f"Dalton in sensor_get_job(): could not find job {id} at {path}.")
        return render_template('/dalton/error.html', jid=id, msg=[f"Job {id} does not exist on disk.  It is either invalid or has been deleted."])


def clear_old_agents():
    global r, AGENT_PURGE_TIME
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            try:
                minutes_ago = int(round((int(time.mktime(time.localtime())) - int(r.get(f"{sensor}-epoch"))) / 60))
#                minutes_ago = AGENT_PURGE_TIME
            except Exception as e:
                logger.error("Error in clear_old_agents(): %s", e)
                # screwed something up, perhaps with Python3 strings...
            if minutes_ago >= AGENT_PURGE_TIME:
                # delete old agents
                r.delete(f"{sensor}-uid")
                r.delete(f"{sensor}-ip")
                r.delete(f"{sensor}-time")
                r.delete(f"{sensor}-epoch")
                r.delete(f"{sensor}-tech")
                r.delete(f"{sensor}-agent_version")
                r.srem("sensors", sensor)


@dalton_blueprint.route('/dalton/sensor', methods=['GET'])
#@login_required()
def page_sensor_default(return_dict = False):
    """the default sensor page"""
    global r
    sensors = {}
    # first clear out old agents ('sensors')
    clear_old_agents()
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            # looks like redis keys are byte
            minutes_ago = int(round((int(time.mktime(time.localtime())) - int(r.get(f"{sensor}-epoch"))) / 60))
            sensors[sensor] = {}
            sensors[sensor]['uid'] = r.get(f"{sensor}-uid")
            sensors[sensor]['ip'] = r.get(f"{sensor}-ip")
            sensors[sensor]['time'] = "{} ({} minutes ago)".format(r.get(f"{sensor}-time"), minutes_ago)
            sensors[sensor]['tech'] = "{}".format(r.get(f"{sensor}-tech"))
            sensors[sensor]['agent_version'] = "{}".format(r.get(f"{sensor}-agent_version"))
    if return_dict:
        return sensors
    else:
        return render_template('/dalton/sensor.html', page='', sensors=sensors)

# validates passed in filename (should be from Flowsynth) to verify
# that it exists and isn't trying to do something nefarious like
# directory traversal
def verify_fs_pcap(fspcap):
    global FS_PCAP_PATH
    # require fspcap to be POSIX fully portable filename
    if not re.match(r"^[A-Za-z0-9\x5F\x2D\x2E]+$", fspcap):
        logger.error("Bad fspcap filename provided: '%s'. Filename must be POSIX fully portable." % fspcap)
        return "Bad pcap filename provided: '%s'" % (fspcap)
    fspcap_path = os.path.join(FS_PCAP_PATH, os.path.basename(fspcap))
    logger.debug("Flowsynth pcap file passed: %s" % fspcap_path)
    if not os.path.isfile(fspcap_path):
        logger.error("fspcap file '%s' not found." % fspcap_path)
        return "File not found: '%s'" % os.path.basename(fspcap)
    return None

"""validate that job_id has expected characters; prevent directory traversal"""
def validate_jobid(jid):
    if not re.match (r'^(teapot_)?[a-zA-Z\d]+$', jid):
        return False
    else:
        return True


@dalton_blueprint.route('/dalton/coverage/job/<jid>', methods=['GET'])
def page_coverage_jid(jid, error=None):
    global JOB_STORAGE_PATH
    global TEMP_STORAGE_PATH
    global RULESET_STORAGE_PATH

    if not re.match(r"^[a-f0-9]{16}$", jid):
        return render_template('/dalton/error.html', jid='', msg=["Not a valid job ID."])

    jobzip_path = os.path.join(f"{JOB_STORAGE_PATH}", f"{jid}.zip")
    if not os.path.isfile(jobzip_path):
        return render_template('/dalton/error.html', jid=jid, msg=[f"Job with ID {jid} does not exist."])

    custom_rules = None
    with zipfile.ZipFile(jobzip_path) as zf:
        manifest = json.loads(zf.read('manifest.json').decode())
        sensor_tech = manifest['sensor-tech'].split('/')[0]
        for f in zf.namelist():
            if f.endswith(f".conf") or f.endswith(f".yaml"):
                engine_conf = zf.read(f).decode()
            elif f == "dalton-custom.rules" and manifest['custom-rules'] == True:
                custom_rules = zf.read(f).decode()
    
    # extend job life by moving file mod date into the future, thereby delaying the usual expiry process
    # subtracting REDIS_EXPIRE so SHARE_EXPIRE matches expectations
    # example: SHARE_EXPIRE = 30 days, REDIS_EXPIRE = 5 days. 
    # The queue delete logic deletes after now + REDIS_EXPIRE. If we don't subtract it now jobs will last 35 days
    now = time.time()
    newtime = now + (SHARE_EXPIRE - REDIS_EXPIRE)
    os.utime(jobzip_path, (newtime,newtime))

    rulesets = get_rulesets(sensor_tech)

    if sensor_tech.lower().startswith('zeek'):
        engine_conf = None

    # enumerate sensor versions based on available sensors and pass them to coverage.html
    #   This way we can dynamically update the submission page as soon as new sensor versions check in
    clear_old_agents()
    sensors = []
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            try:
                tech = r.get("%s-tech" % sensor)
                if tech.startswith(sensor_tech):
                    if tech not in sensors:
                        sensors.append(tech)
            except Exception as e:
                return render_template('/dalton/error.html', jid=None, msg="Error getting sensor list for %s.  Error:\n%s" % (tech, e))
        try:
            # May 2019 - DRW - I'd prefer that non-rust sensors of the same version get listed before
            #  rust enabled sensors so adding this extra sort. Can/should probably be removed in year or two.
            sensors.sort(reverse=False)
            # sort by version number; ignore "rust_" prefix
            sensors.sort(key=lambda v:LooseVersion(prefix_strip(v.split('/', 2)[1], prefixes=["rust_"])), reverse=True)
        except Exception as e:
            try:
                sensors.sort(key=LooseVersion, reverse=True)
            except Exception as ee:
                sensors.sort(reverse=True)
        logger.debug(f"In page_coverage_default() - sensors:\n{sensors}")

    job_ruleset = manifest.get('prod-ruleset')
    if job_ruleset:
        rulesets.insert(0, [f"{jid} ruleset", jobzip_path])

    return render_template('/dalton/coverage.html', sensor_tech=sensor_tech, rulesets=rulesets, error=error, engine_conf=engine_conf, sensors=sensors, fspcap=None, max_pcaps=MAX_PCAP_FILES, manifest=manifest, custom_rules=custom_rules)

@dalton_blueprint.route('/dalton/coverage/<sensor_tech>/', methods=['GET'])
#@login_required()
def page_coverage_default(sensor_tech, error=None):
    """the default coverage wizard page"""
    global CONF_STORAGE_PATH, MAX_PCAP_FILES
    global r
    ruleset_dirs = []
    sensor_tech = sensor_tech.split('-')[0]
    conf_dir = os.path.join(CONF_STORAGE_PATH, clean_path(sensor_tech))
    if sensor_tech is None:
        return render_template('/dalton/error.html', jid='', msg=["No Sensor technology selected for job."])
    elif not re.match(r"^[a-zA-Z0-9\_\-\.]+$", sensor_tech):
        return render_template('/dalton/error.html', jid='', msg=[f"Invalid Sensor technology requested: {sensor_tech}"])
    elif sensor_tech == 'summary':
        return render_template('/dalton/error.html', jid='', msg=["Page expired.  Please resubmit your job or access it from the queue."])

    if not os.path.isdir(conf_dir) and not sensor_tech.startswith('zeek'):
        return render_template('/dalton/error.html', jid='', msg=[f"No engine configuration directory for '{sensor_tech}' found ({conf_dir})."])

    # pcap filename passed in from Flowsynth
    fspcap = None
    try:
        fspcap = request.args['fspcap']
        err_msg = verify_fs_pcap(fspcap)
        if err_msg != None:
            return render_template('/dalton/error.html', jid='', msg=[f"{err_msg}"])
    except:
        fspcap = None

    # get list of rulesets based on engine
    rulesets = get_rulesets(sensor_tech)

    # enumerate sensor versions based on available sensors and pass them to coverage.html
    #   This way we can dynamically update the submission page as soon as new sensor versions check in
    clear_old_agents()
    sensors = []
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            try:
                tech = r.get("%s-tech" % sensor)
                if tech.startswith(sensor_tech):
                    if tech not in sensors:
                        sensors.append(tech)
            except Exception as e:
                return render_template('/dalton/error.html', jid=None, msg="Error getting sensor list for %s.  Error:\n%s" % (tech, e))
        try:
            # May 2019 - DRW - I'd prefer that non-rust sensors of the same version get listed before
            #  rust enabled sensors so adding this extra sort. Can/should probably be removed in year or two.
            sensors.sort(reverse=False)
            # sort by version number; ignore "rust_" prefix
            sensors.sort(key=lambda v:LooseVersion(prefix_strip(v.split('/', 2)[1], prefixes=["rust_"])), reverse=True)
        except Exception as e:
            try:
                sensors.sort(key=LooseVersion, reverse=True)
            except Exception as ee:
                sensors.sort(reverse=True)
        logger.debug(f"In page_coverage_default() - sensors:\n{sensors}")
    # get conf or yaml file if sensor supports it
    engine_conf = None
    # return the engine.conf from the first sensor in the list which is sorted (see above)
    # and should be the most recent sensor version (depends on lexical sort done above). It
    # is also the sensor version that is checked by default on the job submission page.
    if len(sensors) > 0:
        try:
            logger.debug("call to get_engine_conf_file(%s)", sensors[0])
            engine_conf = get_engine_conf_file(sensors[0])
        except Exception as e:
            logger.error("Could not process response from get_engine_conf_file(): %s", e)
            engine_conf = "# not found"
    else:
        # no sensors available.
        engine_conf = "# not found"
    return render_template('/dalton/coverage.html', sensor_tech=sensor_tech, rulesets=rulesets, error=error, engine_conf=engine_conf, sensors=sensors, fspcap=fspcap, max_pcaps=MAX_PCAP_FILES)

@dalton_blueprint.route('/dalton/job/<jid>')
#@auth_required()
def page_show_job(jid):
    global r
    tech = r.get("%s-tech" % jid)
    status = get_job_status(jid)

    if not status:
        # job doesn't exist
        # expire (delete) all keys related to the job just in case to prevent memory leaks
        expire_all_keys(jid)
        return render_template('/dalton/error.html', jid=jid, msg=["Invalid Job ID. Job may have expired.", "By default, jobs are only kept for %d seconds; teapot jobs are kept for %s seconds." % (REDIS_EXPIRE, TEAPOT_REDIS_EXPIRE)])
    elif int(status) != STAT_CODE_DONE:
        # job is queued or running
        return render_template('/dalton/coverage-summary.html', page='', job_id=jid, tech=tech)
    else:
        # job exists and is done
        ids = r.get(f"{jid}-ids")
        perf = r.get(f"{jid}-perf")
        alert = r.get(f"{jid}-alert")
        error = r.get(f"{jid}-error")
        total_time = r.get(f"{jid}-time")
        alert_detailed = r.get(f"{jid}-alert_detailed")

        try:
            zeek_json = r.get(f"{jid}-zeek_json")
        except Exception as e:
            #logger.debug(f"Problem getting {jid}-zeek_json:\n{e}")
            zeek_json = "False"

        try:
            # this gets passed as json with log description as key and log contents as value
            # attempt to load it as json before we pass it to job.html
            other_logs = json.loads(r.get(f"{jid}-other_logs"))
            if tech.startswith('zeek') and zeek_json == "False":
                for other_log in other_logs:
                    other_logs[other_log] = parseZeekASCIILog(other_logs[other_log])
        except Exception as e:
            # if <jid>-other_logs is empty then error, "No JSON object could be decoded" will be thrown so just handling it cleanly
            other_logs = ""
            #logger.error("could not load json other_logs:\n%s\n\nvalue:\n%s" % (e,r.get("%s-other_logs" % jid)))
        try:
            eve = r.get(f"{jid}-eve")
        except Exception as e:
            #logger.debug(f"Problem getting {jid}-eve log:\n{e}")
            eve = ""
        event_types = []
        if len(eve) > 0:
            # pull out all the EVE event types
            try:
                eve_list = [json.loads(line) for line in eve.splitlines()]
                event_types = set([item['event_type'] for item in eve_list if 'event_type' in item])
                if len(event_types) > 0:
                    event_types = sorted(event_types)
            except Exception as e:
                logger.error(f"Problem parsing EVE log for jobid {jid}:\n{e}")
        # parse out custom rules option and pass it?
        custom_rules = False
        try:
            debug = r.get("%s-debug" % jid)
        except Exception as e:
            debug = ''
        overview = {}
        if (alert != None):
            overview['alert_count'] = get_alert_count(jid)
        else:
            overview['alert_count'] = 0
        if (error == ""):
            overview['status'] = 'Success'
        else:
            overview['status'] = 'Error'

        return render_template('/dalton/job.html', overview=overview,page = '',
                               jobid = jid, ids=ids, perf=perf, alert=alert,
                               error=error, debug=debug, total_time=total_time,
                               tech=tech, custom_rules=custom_rules,
                               alert_detailed=alert_detailed, other_logs=other_logs,
                               eve_json=eve, event_types=event_types, zeek_json=zeek_json)

# sanitize passed in filename (string) and make it POSIX (fully portable)
def clean_filename(filename):
    return re.sub(r"[^a-zA-Z0-9\_\-\.]", "_", filename)

# handle duplicate filenames (e.g. same pcap sumbitted more than once)
#  by renaming pcaps with same name
def handle_dup_names(filename, pcap_files, job_id, dupcount):
    for pcap in pcap_files:
        if pcap['filename'] == filename:
            filename = "%s_%s_%d.pcap" % (os.path.splitext(filename)[0], job_id, dupcount[0])
            dupcount[0] += 1
            break
    return filename

# extracts files from an archive and add them to the list to be
#  included with the Dalton job
def extract_pcaps(archivename, pcap_files, job_id, dupcount):
    global TEMP_STORAGE_PATH
    # Note: archivename already sanitized
    logger.debug("Attempting to extract pcaps from  file '%s'" % os.path.basename(archivename))
    if archivename.lower().endswith('.zip'):
        # Apparently python zipfile module does extraction using Python and not something
        #  like C and it is super slow for a zipfile that isn't small in size. So
        #  to speed things up, kick out to 7z on the system which is quite fast but not my
        #  first choice. Still use zipfile module to process archive and get filenames.
        try:
            if not zipfile.is_zipfile(archivename):
                msg = "File '%s' is not recognized as a valid zip file." % os.path.basename(archivename)
                logger.error(msg)
                return msg
            files_to_extract = []
            zf = zipfile.ZipFile(archivename, mode='r')
            for file in zf.namelist():
                logger.debug("Processing file '%s' from ZIP archive" % file)
                if file.endswith('/') or "__MACOSX/" in file:
                    continue
                filename = clean_filename(os.path.basename(file))
                if os.path.splitext(filename)[1].lower() not in ['.pcap', '.pcapng', '.cap']:
                    logger.warn("Not adding file '%s' from archive '%s': '.pcap', '.cap', or '.pcapng' extension required." % (file, os.path.basename(archivename)))
                    # just skip the file, and move on (and log it)
                    continue
                files_to_extract.append(file)
            zf.close()

            if len(files_to_extract) > 0:
                # make temporary location for extracting with 7z
                tempd = tempfile.mkdtemp()
                logger.debug("temp directory for 7z: %s" % tempd)
                # try password 'infected' if password on archive
                p7z_command = ['7z', 'x', archivename, '-pinfected', '-y', "-o%s" % tempd] + files_to_extract
                # does 7z handle invalid/filenames or should more sanitization be attempted?
                logger.debug("7z command: %s" % p7z_command)
                # I'm not convinced that 7z outputs to stderr
                p7z_out = subprocess.Popen(p7z_command, shell=False, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.read()
                if b"Everything is Ok" not in p7z_out and b"Errors: " in p7z_out:
                    logger.error("Problem extracting ZIP archive '%s': %s" % (os.path.basename(archivename), p7z_out))
                    raise Exception("p7zip error. See logs for details")
                logger.debug("7z out: %s" % p7z_out)

                # move files; handle duplicate filenames
                for file in files_to_extract:
                    filename = clean_filename(os.path.basename(file))
                    filename = handle_dup_names(filename, pcap_files, job_id, dupcount)
                    pcappath = os.path.join(TEMP_STORAGE_PATH, job_id, filename)
                    pcapsrc = os.path.join(tempd, file)
                    # copy
                    shutil.move(pcapsrc, pcappath)
                    pcap_files.append({'filename': filename, 'pcappath': pcappath})
                    logger.debug("Successfully extracted and added pcap file '%s'" % os.path.basename(filename))
                # cleanup
                shutil.rmtree(tempd)

        except Exception as e:
            msg = "Problem extracting ZIP file '%s': %s" % (os.path.basename(archivename), e)
            logger.error(msg)
            logger.debug("%s" % traceback.format_exc())
            return msg
    elif os.path.splitext(archivename)[1].lower() in ['.gz', '.gzip'] and \
         os.path.splitext(os.path.splitext(archivename)[0])[1].lower() not in ['.tar']:
        # gzipped file
        try:
            filename =  os.path.basename(os.path.splitext(archivename)[0])
            logger.debug("Decompressing gzipped file '%s'" % filename)
            with gzip.open(archivename, 'rb') as gz:
                filename = handle_dup_names(filename, pcap_files, job_id, dupcount)
                pcappath = os.path.join(TEMP_STORAGE_PATH, job_id, filename)
                fh = open(pcappath, 'wb')
                fh.write(gz.read())
                fh.close()
                pcap_files.append({'filename': filename, 'pcappath': pcappath})
                logger.debug("Added %s" % filename)
        except Exception as e:
            msg = "Problem extracting gzip file '%s': %s" % (os.path.basename(archivename), e)
            logger.error(msg)
            logger.debug("%s" % traceback.format_exc())
            return msg
    elif os.path.splitext(archivename)[1].lower() in ['.bz2'] and \
         os.path.splitext(os.path.splitext(archivename)[0])[1].lower() not in ['.tar']:
        # bzip2 file
        try:
            filename =  os.path.basename(os.path.splitext(archivename)[0])
            logger.debug("Decompressing bzip2 file '%s'" % filename)
            with bz2.BZ2File(archivename, 'rb') as bz:
                filename = handle_dup_names(filename, pcap_files, job_id, dupcount)
                pcappath = os.path.join(TEMP_STORAGE_PATH, job_id, filename)
                fh = open(pcappath, 'wb')
                fh.write(bz.read())
                fh.close()
                pcap_files.append({'filename': filename, 'pcappath': pcappath})
                logger.debug("Added %s" % filename)
        except Exception as e:
            msg = "Problem extracting bzip2 file '%s': %s" % (os.path.basename(archivename), e)
            logger.error(msg)
            logger.debug("%s" % traceback.format_exc())
            return msg
    else:
        try:
            archive = tarfile.open(archivename, mode="r:*")
            for file in archive.getmembers():
                logger.debug("Processing file '%s' from archive" % file.name)
                if not file.isfile():
                    logger.warn("Not adding member '%s' from archive '%s': not a file." % (file.name, os.path.basename(archivename)))
                    continue
                filename = clean_filename(os.path.basename(file.name))
                if os.path.splitext(filename)[1].lower() not in ['.pcap', '.pcapng', '.cap']:
                    logger.warn("Not adding file '%s' from archive '%s': '.pcap', '.cap', or '.pcapng' extension required." % (file.name, os.path.basename(archivename)))
                    # just skip the file, and move on (and log it)
                    continue
                filename = handle_dup_names(filename, pcap_files, job_id, dupcount)
                pcappath = os.path.join(TEMP_STORAGE_PATH, job_id, filename)
                fh = open(pcappath, 'wb')
                contentsfh = archive.extractfile(file)
                fh.write(contentsfh.read())
                fh.close()
                pcap_files.append({'filename': filename, 'pcappath': pcappath})
                logger.debug("Added %s" % filename)
            archive.close()
        except Exception as e:
            msg = "Problem extracting archive file '%s': %s" % (os.path.basename(archivename), e)
            logger.error(msg)
            logger.debug("%s" % traceback.format_exc())
            return msg
    return None

#  abstracting the job submission method away from the HTTP POST and creating this
#   function so that it can be called easier (e.g. from an API)
def submit_job():
    logger.debug("submit_job() called")
    # never finished coding this...
    # TODO: API call that accepts a job zipfile and queues it up for an agent?
    #       would have to beef up input validation on agent probably....

@dalton_blueprint.route('/dalton/coverage/summary', methods=['POST'])
#@auth_required()
# ^^ can change and add resource and group permissions if we want to restrict who can submit jobs
def page_coverage_summary():
    """ Handle job submission from UI.
    """
    # user submitting a job to Dalton via the web interface
    global JOB_STORAGE_PATH
    global TEMP_STORAGE_PATH
    global RULESET_STORAGE_PATH
    global r
    global STAT_CODE_QUEUED
    global FS_PCAP_PATH
    global MAX_PCAP_FILES

    verify_temp_storage_path()
    digest = hashlib.md5()

    prod_ruleset_name = None

    # get the user who submitted the job .. not implemented
    user = "undefined"

    #generate job_id based of pcap filenames and timestamp
    digest.update(str(datetime.datetime.now()).encode('utf-8'))
    digest.update(str(random.randrange(96313375)).encode('utf-8'))
    job_id = digest.hexdigest()[0:16]   #this is a temporary job id for the filename

    # store the pcaps offline temporarily
    # make temp job directory so there isn't a race condition if more
    # than one person submits a pcap with the same filename at the same time
    if os.path.exists(os.path.join(TEMP_STORAGE_PATH, job_id)):
        shutil.rmtree(os.path.join(TEMP_STORAGE_PATH, job_id))
    os.makedirs(os.path.join(TEMP_STORAGE_PATH, job_id))

    # list of dicts that have filename: and pcappath: entries for pcap files on disk to include in job
    pcap_files = []
    form_pcap_files = []
    # pcapfilename from Flowsynth; on local (Dalton controller) disk
    if request.form.get("fspcap"):
        fspcap = request.form.get("fspcap")
        err_msg = verify_fs_pcap(fspcap)
        if err_msg:
            delete_temp_files(job_id)
            return render_template('/dalton/error.html', jid='', msg=[err_msg])
        pcap_files.append({'filename': fspcap, 'pcappath': os.path.join(FS_PCAP_PATH, os.path.basename(fspcap))})

    bSplitCap = False
    try:
        if request.form.get("optionSplitcap"):
            bSplitCap = True
    except:
        pass

    # grab the user submitted files from the web form (max number of arbitrary files allowed on the web form
    # governed by max_pcap_files variable in dalton.conf)
    # note that these are file handle objects? have to get filename using .filename
    # make this a list so I can pass by reference
    dupcount = [0]
    job_zip = request.form.get("job-zip")
    if (job_zip != None and re.match(r"^[a-f0-9]{16}\.zip$", job_zip)):
        filename = clean_filename(os.path.basename(job_zip))
        filepath = os.path.join(JOB_STORAGE_PATH, filename)
        if not os.path.isfile(filepath):
            return render_template('/dalton/error.html', jid='', msg=[f"Zip file for {filename} does not exist"])
        err_msg = extract_pcaps(filepath, pcap_files, job_id, dupcount)
        if err_msg:
            delete_temp_files(job_id)
            return render_template('/dalton/error.html', jid='', msg=[err_msg])

    for i in range(MAX_PCAP_FILES):
        try:
            coverage_pcaps = request.files.getlist("coverage-pcap%d" % i)
            for pcap_file in coverage_pcaps:
                if (pcap_file != None and pcap_file.filename != None and pcap_file.filename != '<fdopen>' and (len(pcap_file.filename) > 0) ):
                    if os.path.splitext(pcap_file.filename)[1].lower() in ['.zip', '.tar', '.gz', '.tgz', '.gzip', '.bz2']:
                        filename = clean_filename(os.path.basename(pcap_file.filename))
                        filename = os.path.join(TEMP_STORAGE_PATH, job_id, filename)
                        pcap_file.save(filename)
                        err_msg = extract_pcaps(filename, pcap_files, job_id, dupcount)
                        if err_msg:
                            delete_temp_files(job_id)
                            return render_template('/dalton/error.html', jid='', msg=[err_msg])
                    else:
                        form_pcap_files.append(pcap_file)
        except:
            logger.debug("%s" % traceback.format_exc())
            pass

    #get the sensor technology and queue name
    sensor_tech = request.form.get('sensor_tech')

    #verify that we have a sensor that can handle the submitted sensor_tech
    valid_sensor_tech = False
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            if r.get("%s-tech" % sensor) == sensor_tech:
                valid_sensor_tech = True
                break
    if not valid_sensor_tech:
        logger.error("Dalton in page_coverage_summary(): Error: user %s submitted a job for invalid sensor tech, '%s'",  user, sensor_tech)
        delete_temp_files(job_id)
        return render_template('/dalton/error.html', jid='', msg=[f"There are no sensors that support sensor technology '{sensor_tech}'."])

    if len(form_pcap_files) == 0 and len(pcap_files) == 0:
        #throw an error, no pcaps submitted
        delete_temp_files(job_id)
        return render_template('/dalton/error.html', jid='', msg=["You must specify a PCAP file."])
    elif (request.form.get('optionProdRuleset') == None and request.form.get('optionCustomRuleset') == None) and not sensor_tech.startswith('zeek'):
        #throw an error, no rules defined
        delete_temp_files(job_id)
        return render_template('/dalton/error.html', jid='', msg=["You must specify at least one ruleset."])
    else:
        # process files from web form
        for pcap_file in form_pcap_files:
            filename = os.path.basename(pcap_file.filename)
            # do some input validation on the filename and try to do some accommodation to preserve original pcap filename
            filename = clean_filename(filename)
            if os.path.splitext(filename)[1] != '.pcap':
                    filename = f"{filename}.pcap"
            # handle duplicate filenames (e.g. same pcap sumbitted more than once)
            filename = handle_dup_names(filename, pcap_files, job_id, dupcount)
            pcappath = os.path.join(TEMP_STORAGE_PATH, job_id, filename)
            pcap_files.append({'filename': filename, 'pcappath': pcappath})
            pcap_file.save(pcappath)

        (sensor_tech_engine, sensor_tech_version) = get_engine_and_version(sensor_tech)
        if sensor_tech_engine is None or sensor_tech_version is None:
            logger.error("Dalton in page_coverage_summary(): Error: user %s submitted a job with invalid sensor tech string, '%s'",  user, sensor_tech)
            delete_temp_files(job_id)
            return render_template('/dalton/error.html', jid='', msg=[f"Bad sensor_tech string submitted: '{sensor_tech}'."])

        # If multiple files submitted to Suricata, merge them here if the
        # Suricata version is < 4.1 since that is when support for multiple pcaps
        # was added.
        if len(pcap_files) > 1 and sensor_tech.startswith("suri") and LooseVersion(sensor_tech_version) < LooseVersion("4.1") and not bSplitCap:
            if not MERGECAP_BINARY:
                logger.error("No mergecap binary; unable to merge pcaps for Suricata job.")
                delete_temp_files(job_id)
                return render_template('/dalton/error.html', jid=job_id, msg=["No mergecap binary found on Dalton Controller.", "Unable to process multiple pcaps for this Suricata job."])
            combined_file = "%s/combined-%s.pcap" % (os.path.join(TEMP_STORAGE_PATH, job_id), job_id)
            mergecap_command = f"{MERGECAP_BINARY} -w {combined_file} -a -F pcap {' '.join([p['pcappath'] for p in pcap_files])}"
            logger.debug("Multiple pcap files sumitted to Suricata, combining the following into one file:  %s", ', '.join([p['filename'] for p in pcap_files]))
            try:
                # validation on pcap filenames done above; otherwise OS command injection here
                mergecap_output = subprocess.Popen(mergecap_command, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.read()
                if len(mergecap_output) > 0:
                    # return error?
                    logger.error("Error merging pcaps with command:\n%s\n\nOutput:\n%s", mergecap_command, mergecap_output)
                    delete_temp_files(job_id)
                    return render_template('/dalton/error.html', jid="<not_defined>", msg=["Error merging pcaps with command:", f"{mergecap_command}", "Output:", f"{mergecap_output}"])
                pcap_files = [{'filename': os.path.basename(combined_file), 'pcappath': combined_file}]
            except Exception as e:
                logger.error("Could not merge pcaps.  Error: %s",  e)
                delete_temp_files(job_id)
                return render_template('/dalton/error.html', jid='', msg=["Could not merge pcaps.  Error:", f"{e}"])

        # get use Suricata Socket Control option
        bSuricataSC = False
        if sensor_tech.startswith("suri") :
            try:
                if request.form.get("optionUseSC"):
                    bSuricataSC = True
            except:
                pass

        # get enable all rules option
        bEnableAllRules = False
        if request.form.get('optionProdRuleset') and request.form.get('optionEnableAllRules'):
            bEnableAllRules = True

        # get showFlowbitAlerts option
        bShowFlowbitAlerts = False
        if request.form.get('optionProdRuleset') and request.form.get('optionShowFlowbitAlerts'):
            bShowFlowbitAlerts = True

        # get track performance option
        bTrackPerformance = False
        if request.form.get('optionPerf'):
            bTrackPerformance = True

        # get return engine statistics option
        bGetEngineStats = False
        try:
            if request.form.get('optionStats'):
                bGetEngineStats = True
        except:
            pass

        # get generate fast pattern option
        bGetFastPattern =  False
        try:
            if request.form.get('optionFastPattern'):
                bGetFastPattern = True
        except:
            pass

        # A 'teapot' job is one that shouldn't be stored for a long period of time; it can be used by
        #   functionality that programmatically analyzes a rule and/or other situations
        #   where the submission data shouldn't be stored for long periods of time (e.g. over an hour).
        #   'teapot' is not an acronym. It's for job runs that are short and stout.
        bteapotJob = False
        # if teapotJob is set, set 'bteapotJob' to 'True'
        try:
            if request.form.get('teapotJob'):
                bteapotJob = True
        except:
            pass

        # used to tell the agent to return pcap data from alerts.
        #   This is only supported (for now) for agents that generate/process unified2 alerts
        #   and return pcap details from them.
        bGetAlertDetailed = False
        try:
            if request.form.get('optionAlertDetailed'):
                bGetAlertDetailed = True
            if sensor_tech_engine == "suricata" and int(sensor_tech_version.split('.')[0]) >= 6:
                bGetAlertDetailed = False
        except:
            pass

        # generate EVE log (only supported by Suricata)
        bGetEveLog = False
        try:
            if request.form.get('optionEveLog'):
                bGetEveLog = True
            if sensor_tech_engine == "suricata" and int(sensor_tech_version.split('.')[0]) < 2:
                bGetEveLog = False
        except:
            pass

        # get other logs (only supported in Suricata for now)
        bGetOtherLogs = False
        try:
            if request.form.get('optionOtherLogs'):
                bGetOtherLogs = True
            # Dump Buffer option valid for Suri >= version 2.1 and Snort >= 2.9.9.0
            if sensor_tech_engine == "suricata" and LooseVersion(sensor_tech_version) < LooseVersion("2.1"):
                bGetBufferDumps = False
            if sensor_tech_engine == "snort" and LooseVersion(sensor_tech_version) < LooseVersion("2.9.9.0"):
                bGetBufferDumps = False
        except:
            pass

        # get dumps from buffers
        bGetBufferDumps = False
        try:
            if request.form.get('optionDumpBuffers'):
                bGetBufferDumps = True
        except:
            pass

        # JSON output for Zeek logs
        boptionZeekJSON = False
        try:
            if request.form.get('optionZeekJSON'):
                boptionZeekJSON = True
        except:
            pass

        #get custom rules (if defined)
        bCustomRules = False
        custom_rules_file = os.path.join(TEMP_STORAGE_PATH, f"{job_id}_custom.rules")
        if request.form.get('optionCustomRuleset') and request.form.get('custom_ruleset'):
            bCustomRules = True
            custom_rules = request.form.get('custom_ruleset')

            # strip out leading newlines and CRLFCRLF in case the sensor does not like it for some reason
            custom_rules = custom_rules.lstrip('\x0A\x0D')
            while re.search(r'\x0D\x0A\x0D\x0A', custom_rules):
                custom_rules = custom_rules.replace('\x0D\x0A\x0D\x0A', '\x0D\x0A')

            # used for automatically generating SID values for ad-hoc rules that don't include them
            sid_base = 806421600
            sid_offset = 1

            # file we will write the custom rules to
            fh = open(custom_rules_file, 'w')
            # check for rule errors (very simple right now)
            for line in custom_rules.split('\n'):
                # strip out trailing whitespace (note: this removes the newline chars too so have to add them back when we write to file)
                line = line.rstrip()
                # strip out leading whitespace to make subsequent matching easier (snort won't complain about leading whitespace though)
                line = line.lstrip()
                # if empty or comment line, continue
                if line == '' or re.search(r'^\s+$', line) or line.startswith('#'):
                    continue
                if (len(line) > 0) and not re.search(r'^[\x00-\x7F]+$', line):
                    fh.close()
                    delete_temp_files(job_id)
                    return render_template('/dalton/error.html', jid='', msg=["Invalid rule. Only ASCII characters are allowed in the literal representation of custom rules.", "Please encode necessary non-ASCII characters appropriately.  Rule:", f"{line}"])
                # some rule validation for Snort and Suricata
                if sensor_tech.startswith('snort') or sensor_tech.startswith('suri'):
                    # rule must start with alert|log|pass|activate|dynamic|drop|reject|sdrop
                    if not re.search(r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop|event_filter|threshold|suppress|rate_filter|detection_filter)\s', line):
                        fh.close()
                        delete_temp_files(job_id)
                        return render_template('/dalton/error.html', jid='', msg=[f"Invalid rule, action (first word in rule) of '{line.split()[0]}' not supported.  Rule:", f"line"])

                    # rule must end in closing parenthesis
                    if not line.endswith(')') and not line.startswith("event_filter") and not line.startswith("threshold") \
                        and not line.startswith("suppress") and not line.startswith("rate_filter") and not line.startswith("detection_filter"):
                        fh.close()
                        delete_temp_files(job_id)
                        return render_template('/dalton/error.html', jid='', msg=["Invalid rule; does not end with closing parenthesis.  Rule:", f"{line}"])

                    # last keyword in the rule must be terminated by a semicolon
                    if not line[:-1].rstrip().endswith(';') and not line.startswith("event_filter") and not line.startswith("threshold") \
                        and not line.startswith("suppress") and not line.startswith("rate_filter") and not line.startswith("detection_filter"):
                        fh.close()
                        delete_temp_files(job_id)
                        return render_template('/dalton/error.html', jid='', msg=["Invalid rule, last rule option must end with semicolon.  Rule:",  f"{line}"])

                    # add sid if not included
                    if not re.search(r'(^[^\x28]+\x28\s*|\s|\x3B)sid\s*\:\s*\d+\s*\x3B', line) and not line.startswith("event_filter") and not line.startswith("threshold") \
                        and not line.startswith("suppress") and not line.startswith("rate_filter") and not line.startswith("detection_filter"):
                        # if no sid in rule, fix automatically instead of throwing an error
                        #return render_template('/dalton/error.html', jid='', msg=["\'sid\' not specified in rule, this will error.  Rule:", "%s" % line])
                        line = re.sub(r'\x29$', " sid:%d;)" % (sid_base + sid_offset), line)
                        sid_offset += 1
                # including newline because it was removed earlier with rstrip()
                fh.write("%s\n" % line)
            fh.close()

        if not sensor_tech:
            delete_temp_files(job_id)
            return render_template('/dalton/error.html', jid="<not_defined>", msg=["Variable 'sensor_tech' not specified.  Please reload the submission page and try again."])

        # get 'Override External_NET - set to any' option
        bOverrideExternalNet = False
        try:
            if request.form.get('overrideExternalNet'):
                bOverrideExternalNet = True
        except:
            pass

        # pre-set IP vars to add to the config if they don't exist.
        # this helps with some rulesets that may use these variables
        # but the variables aren't in the default config.
        ipv2add = {'RFC1918': "[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]"
                  }

        conf_file = request.form.get('custom_engineconf')
        if not conf_file and not sensor_tech.startswith('zeek'):
            delete_temp_files(job_id)
            return render_template('/dalton/error.html', jid='', msg=["No configuration file provided."])

        bLockConfig = False

        if sensor_tech.startswith('suri'):
            # just in case someone edited and didn't quote a boolean
            conf_file = re.sub(r'(\w):\x20+(yes|no)([\x20\x0D\x0A\x23])', '\g<1>: "\g<2>"\g<3>', conf_file)
            try:
                # read in yaml
                config = yaml.round_trip_load(conf_file, version=(1,1), preserve_quotes=True)
                # add some IP vars common to some rulesets
                try:
                    for v in ipv2add:
                        if v not in config['vars']['address-groups']:
                            config['vars']['address-groups'][v] = ipv2add[v]
                except Exception as e:
                    logger.warn("(Not Fatal) Problem customizing Suricata variables; your YAML may be bad. %s",  e)
                    logger.debug(f"{traceback.format_exc()}")
                # set EXTERNAL_NET to 'any' if option set
                try:
                    if bOverrideExternalNet:
                        if not 'EXTERNAL_NET' in config['vars']['address-groups']:
                            logger.warn("EXTERNAL_NET IP variable not set in config; setting to 'any'")
                        config['vars']['address-groups']['EXTERNAL_NET'] = 'any'
                        logger.debug("Set 'EXTERNAL_NET' IP variable to 'any'")
                except Exception as e:
                    logger.warn("(Not Fatal) Problem overriding EXTERNAL_NET: %s" % e)
                    logger.debug("%s" % traceback.format_exc())
                # first, do rule includes
                # should references to other rule files be removed?
                removeOtherRuleFiles = True
                if not 'rule-files' in config or removeOtherRuleFiles:
                    config['rule-files'] = []
                if request.form.get('optionProdRuleset'):
                    # some code re-use here
                    prod_ruleset_name = os.path.basename(request.form.get('prod_ruleset'))
                    if prod_ruleset_name.startswith(JOB_STORAGE_PATH) and prod_ruleset_name.endswith('.zip'):
                        jobzip_path = os.path.join(JOB_STORAGE_PATH, os.path.basename(prod_ruleset_name))
                        with zipfile.ZipFile(jobzip_path) as zf:
                            for f in zf.namelist():
                                if f.endswith(".rules") and f != "dalton-custom.rules":
                                    prod_ruleset_name = f
                                    break
                    elif not prod_ruleset_name.endswith(".rules"):
                        prod_ruleset_name = "%s.rules" % prod_ruleset_name
                    config['rule-files'].append("%s" % prod_ruleset_name)
                if bCustomRules:
                    config['rule-files'].append("dalton-custom.rules")

                # remove default rule path; added back on agent
                if 'default-rule-path' in config:
                    config.pop('default-rule-path', None)

                # make minimum log level "info"
                if "logging" in config and "default-log-level" in config['logging'] and config['logging']['default-log-level']  == "notice":
                    config['logging']['default-log-level']  = "info"

                for citem in ['outputs', 'logging']:
                    # set outputs
                    if citem not in config:
                        logger.warn(f"No '{citem}' section in Suricata YAML. This may be a problem....")
                        # going to try to build this from scratch but Suri still may not like it
                        config[f"{citem}"] = []

                # apparently with this version of ruamel.yaml and the round trip load, some things aren't
                #  an ordered dict but a list...
                llist =[list(config['logging']['outputs'][i].keys())[0] for i in range(0, len(config['logging']['outputs']))]
                olist =[list(config['outputs'][i].keys())[0] for i in range(0, len(config['outputs']))]

                # Suricata log. Hard code location for use in socket control
                slog_level = "info"
                if 'file' in llist:
                    try:
                        slog_level = config['logging']['outputs'][llist.index('file')]['file']['level']
                    except Exception as e:
                        logger.warn("Unable to get log level from config (logging->outputs->file->level): %s" % e)
                        pass
                file_config = {'file': {'enabled': True, \
                                                'filename': "/tmp/dalton-suricata.log", \
                                                'level': f"{slog_level}"}}
                if 'file' in llist:
                    config['logging']['outputs'][llist.index('file')] = file_config
                else:
                    config['logging']['outputs'].append(file_config)

                # fast.log
                fast_config = {'fast': {'enabled': True, \
                                             'filename': "dalton-fast.log", \
                                             'append': True}}
                if 'fast' in olist:
                    config['outputs'][olist.index('fast')] = fast_config
                else:
                    config['outputs'].append(fast_config)

                # unified2 logging
                if bGetAlertDetailed:
                    deployment = "reverse"
                    header = "X-Forwarded-For"
                    if 'unified2-alert' in olist:
                        try:
                            deployment = config['outputs'][olist.index('unified2-alert')]['unified2-alert']['xff']['deployment']
                        except Exception as e:
                            logger.debug("Could not get outputs->unified2-alert->xff->deployment.  Using default value of '%s'" % deployment)
                        try:
                            header = config['outputs'][olist.index('unified2-alert')]['unified2-alert']['xff']['header']
                        except Exception as e:
                            logger.debug("Could not get outputs->unified2-alert->xff->header.  Using default value of '%s'" % header)
                    u2_config = {'unified2-alert': {'enabled': True, \
                                 'filename': "unified2.dalton.alert", \
                                 'xff': {'enabled': True, 'mode': 'extra-data', \
                                         'deployment': deployment, 'header': header}}}
                    if 'unified2-alert' in olist:
                        config['outputs'][olist.index('unified2-alert')] = u2_config
                    else:
                        config['outputs'].append(u2_config)

                #stats
                stats_config = {'stats': {'enabled': True, \
                                                'filename': "dalton-stats.log", \
                                                'totals': True, \
                                                'threads': False}}
                if 'stats' in olist:
                    config['outputs'][olist.index('stats')] = stats_config
                else:
                    config['outputs'].append(stats_config)


                if not "profiling" in config:
                    config['profiling'] = {}

                # always return Engine stats for Suri
                config['profiling']['packets'] = {'enabled': True, \
                                                'filename': "dalton-packet_stats.log", \
                                                'append': True}

                if bGetOtherLogs:
                    # alert-debug
                    alert_debug_config = {'alert-debug': {'enabled': True, \
                                                'filename': "dalton-alert_debug.log", \
                                                'append': True}}
                    if 'alert-debug' in olist:
                        config['outputs'][olist.index('alert-debug')] = alert_debug_config
                    else:
                        config['outputs'].append(alert_debug_config)

                    # http
                    http_config = {'http-log': {'enabled': True, \
                                                'filename': "dalton-http.log", \
                                                'append': True}}
                    if 'http-log' in olist:
                        config['outputs'][olist.index('http-log')] = http_config
                    else:
                        config['outputs'].append(http_config)

                    # tls
                    tls_config = {'tls-log': {'enabled': True, \
                                                'filename': "dalton-tls.log", \
                                                'append': True}}
                    if 'tls-log' in olist:
                        config['outputs'][olist.index('tls-log')] = tls_config
                    else:
                        config['outputs'].append(tls_config)

                    # dns
                    dns_config = {'dns-log': {'enabled': True, \
                                              'filename': "dalton-dns.log", \
                                              'append': True}}
                    # Support for DNS log dropped in Suricata 5 :(
                    if LooseVersion(sensor_tech_version) < LooseVersion("5"):
                        if 'dns-log' in olist:
                            config['outputs'][olist.index('dns-log')] = dns_config
                        else:
                            config['outputs'].append(dns_config)

                # EVE Log
                try:
                    if bGetEveLog:
                        # Enable EVE Log
                        config['outputs'][olist.index('eve-log')]['eve-log']['enabled'] = True

                        # set filename
                        config['outputs'][olist.index('eve-log')]['eve-log']['filename'] = "dalton-eve.json"

                        # disable EVE TLS logging if Suricata version is < 3.1 which doesn't support multiple
                        # loggers. This mixing of dicts and lists is onerous....
                        # doing this one at a time (two passes) since we are iterating over the structure
                        # we want to edit AND we are using list indexes.
                        # Also, the yaml will be represented differently based on the values (e.g. string vs ordered dict).
                        # Instead of trying to check everything every time, just catch the exception(s) and move on. The
                        # stuff we want disabled will still get disabled despite the exceptions along the way.
                        if LooseVersion(sensor_tech_version) < LooseVersion("3.1"):
                            for i in range(0,len(config['outputs'][olist.index('eve-log')]['eve-log']['types'])):
                                try:
                                    if list(config['outputs'][olist.index('eve-log')]['eve-log']['types'][i].keys())[0] == 'alert':
                                        # apparently this is supported -- http://suricata.readthedocs.io/en/latest/output/eve/eve-json-output.html
                                        config['outputs'][olist.index('eve-log')]['eve-log']['types'][i]['alert'].pop('tls', None)
                                        logger.debug("Removed outputs->eve-log->types->alert->tls")
                                        break
                                except Exception as e:
                                    #logger.debug("Possible issue when removing outputs->eve-log->types->alert->tls (EVE TLS log). Error: %s" % e)
                                    pass

                            for i in range(0,len(config['outputs'][olist.index('eve-log')]['eve-log']['types'])):
                                try:
                                    if list(config['outputs'][olist.index('eve-log')]['eve-log']['types'][i].keys())[0] == 'tls':
                                        del config['outputs'][olist.index('eve-log')]['eve-log']['types'][i]
                                        logger.debug("Removed outputs->eve-log->types->tls")
                                        break
                                except Exception as e:
                                    #logger.debug("Possible issue when removing outputs->eve-log->types->tls (EVE TLS log). Error: %s" % e)
                                    pass
                    else:
                        # disable EVE Log if Suricata version supports it
                        if int(sensor_tech_version.split('.')[0]) >= 2:
                            # disable EVE Log here
                            config['outputs'][olist.index('eve-log')]['eve-log']['enabled'] = False
                except Exception as e:
                    logger.warn("Problem editing eve-log section of config: %s" % e)
                    pass

                # set filename for rule and keyword profiling
                if bTrackPerformance:
                    # rule profiling
                    if not "rules" in config['profiling']:
                        config['profiling']['rules'] = {'enabled': True, \
                                                        'filename': "dalton-rule_perf.log", \
                                                        'append': True, \
                                                        'sort': "avgticks", \
                                                        'limit': 1000, \
                                                        'json': False}
                    else:
                        config['profiling']['rules']['enabled'] = True
                        config['profiling']['rules']['filename'] = "dalton-rule_perf.log"
                        config['profiling']['rules']['json'] = False
                    # keyword profiling
                    # is this supported by older Suri versions? If not Suri will ignore when loading YAML
                    if 'keywords' in config['profiling']:
                        config['profiling']['keywords'] = {'enabled': True, \
                                                           'filename': "dalton-keyword_perf.log", \
                                                           'append': True}

                if bGetBufferDumps:
                    buff_dump_config = {'lua': {'enabled': True, \
                                        'scripts-dir': "/opt/dalton-agent", \
                                        'scripts': ["http.lua","tls.lua","dns.lua"]}}

                    if 'lua' in olist: # someone added something
                        config['outputs'][olist.index('lua')] = buff_dump_config
                    else:
                        config['outputs'].append(buff_dump_config)

                # write out
                engine_conf_file = os.path.join(TEMP_STORAGE_PATH, f"{job_id}_suricata.yaml")
                engine_conf_fh = open(engine_conf_file, "w")
                engine_conf_fh.write(yaml.round_trip_dump(config, version=(1,1), explicit_start=True))
                engine_conf_fh.close()
            except Exception as e:
                logger.error("Problem processing YAML file(s): %s", e)
                logger.debug("%s", traceback.format_exc())
                delete_temp_files(job_id)
                return render_template('/dalton/error.html', jid='', msg=["Error processing YAML file(s):", f"{e}"])
        else:
            engine_conf_file = None
            if sensor_tech.startswith('snort'):
                # tweak Snort conf file
                new_conf = ''
                perf_found = False
                external_net_found = False
                ipv2add_copy = copy.deepcopy(ipv2add)
                # calling splitlines line this (without 'True' arg) removes ending newline char(s)
                lines = iter(conf_file.splitlines())
                while True:
                    try:
                        line = next(lines)
                        # don't bother keeping comments or empty lines....
                        if line.lstrip(' ').startswith('#') or line.lstrip(' ').rstrip(' ') == '':
                            # uncomment below to keep comments and empty lines
                            #new_conf += f"{line}\n"
                            continue

                        # tweak variables
                        if re.search(r'^(var|portvar|ipvar)\s', line):

                            # add some IP vars common to some rulesets
                            try:
                                for v in ipv2add:
                                    if line.startswith(f"ipvar {v}"):
                                        # can't modify list we are iterating over so delete from copy
                                        ipv2add_copy.pop(v)
                            except Exception as e:
                                logger.warn("(Not Fatal) Problem customizing Snort variables: %s", e)
                                logger.debug("%s" % traceback.format_exc())
                            if line.startswith("ipvar EXTERNAL_NET "):
                                external_net_found = True
                                if bOverrideExternalNet:
                                    line = "ipvar EXTERNAL_NET any"
                                    logger.debug("Set 'EXTERNAL_NET' ipvar to 'any'")
                            if line.startswith("var EXTERNAL_NET "):
                                external_net_found = True
                                if bOverrideExternalNet:
                                    logger.debug("Set 'EXTERNAL_NET' var to 'any'")
                                    line = "var EXTERNAL_NET any"

                        # add directive for rule profiling, if requested
                        if bTrackPerformance:
                            if line.startswith("config profile_rules:"):
                                perf_found = True
                                while line.endswith("\\"):
                                    line = line.rstrip('\\') + next(lines)
                                if "filename " in line:
                                    line = re.sub(r'filename\s+[^\s\x2C]+', 'filename dalton-rule_perf.log', line)
                                else:
                                    line += ", filename dalton-rule_perf.log append"

                        new_conf += f"{line}\n"
                    except StopIteration:
                        break

                if bTrackPerformance and not perf_found:
                    new_conf += "\nconfig profile_rules: print 1000, sort avg_ticks, filename dalton-rule_perf.log append\n"

                # add 'ipvar EXTERNAL_NET any' if not present and Override EXTERNAL_NET option set
                if bOverrideExternalNet and not external_net_found:
                    new_conf += "ipvar EXTERNAL_NET any\n"

                # add in other common variables if they aren't defined
                for v in ipv2add_copy:
                    new_conf += f"ipvar {v} {ipv2add_copy[v]}\n"

                conf_file = new_conf
                engine_conf_file = os.path.join(TEMP_STORAGE_PATH, f"{job_id}_snort.conf")
            elif sensor_tech.startswith('zeek'):
                engine_conf_file = None
            else:
                logger.warn("Unexpected sensor_tech value submitted: %s", sensor_tech)
                engine_conf_file = os.path.join(TEMP_STORAGE_PATH, f"{job_id}_engine.conf")

            if not sensor_tech.startswith('zeek'):
                # write it out
                with open(engine_conf_file, "w") as engine_conf_fh:
                    engine_conf_fh.write(conf_file)

        # create jid (job identifier) value
        digest = hashlib.md5()
        digest.update(job_id.encode('utf-8'))
        digest.update(sensor_tech.encode('utf-8'))

        splitcap_jid_list = []

        for splitcap in pcap_files:
            digest.update(splitcap['filename'].encode('utf-8'))
            jid = digest.hexdigest()[0:16]

            #Create the job zipfile. This will contain the file 'manifest.json', which is also queued.
            #And place the rules file, config file, and test PCAPs within the zip file
            # for splitcap (creating separate jobs for each pcap), only the pcap file and manifest are
            # modified but seems easier and just as fast to go thru the whole (new) zip file creation
            # process here.
            if not os.path.exists(JOB_STORAGE_PATH):
                os.makedirs(JOB_STORAGE_PATH)
            zf_path = None
            if bteapotJob:
                # add 'teapot_' to the beginning of the jid to distinguish teapot jobs.  Among other things, this
                # makes it so cron or whatever can easily delete teapot jobs on a different schedule if need be.
                jid = f"teapot_{jid}"
            if bSplitCap:
                set_job_status_msg(jid, f"Creating job for pcap '{os.path.basename(splitcap['filename'])}'...")
            zf_path = os.path.join(f"{JOB_STORAGE_PATH}", f"{jid}.zip")
            zf = zipfile.ZipFile(zf_path, mode='w')
            try:
                if bSplitCap:
                    zf.write(splitcap['pcappath'], arcname=os.path.basename(splitcap['filename']))
                else:
                    for pcap in pcap_files:
                        zf.write(pcap['pcappath'], arcname=os.path.basename(pcap['filename']))
                if request.form.get('optionProdRuleset'):
                    ruleset_path = request.form.get('prod_ruleset')
                    if not ruleset_path:
                        delete_temp_files(job_id)
                        return render_template('/dalton/error.html', jid=jid, msg=["No defined ruleset provided."])
                    if ruleset_path.startswith(JOB_STORAGE_PATH) and ruleset_path.endswith('.zip'):
                        jobzip_path = os.path.join(JOB_STORAGE_PATH, os.path.basename(ruleset_path))
                        if not os.path.exists(jobzip_path):
                            delete_temp_files(job_id)
                            return render_template('/dalton/error.html', jid=jid, msg=["Ruleset does not exist on Dalton Controller: %s; ruleset-path: %s" % (prod_ruleset_name, ruleset_path)])
                        with zipfile.ZipFile(jobzip_path) as jobzf:
                            for f in jobzf.namelist():
                                if f.endswith(".rules") and f != "dalton-custom.rules":
                                    ruleset_path = os.path.join(TEMP_STORAGE_PATH, job_id, f)
                                    open(ruleset_path, 'w').write(jobzf.read(f).decode())
                                    prod_ruleset_name = os.path.basename(ruleset_path)
                                    break
                    if not prod_ruleset_name: # if Suri job, this is already set above
                        prod_ruleset_name = os.path.basename(ruleset_path)
                        if not prod_ruleset_name.endswith(".rules"):
                            prod_ruleset_name = "%s.rules" % prod_ruleset_name
                    logger.debug("ruleset_path = %s" % ruleset_path)
                    logger.debug("Dalton in page_coverage_summary():   prod_ruleset_name: %s" % (prod_ruleset_name))
                    if (not ruleset_path.startswith(RULESET_STORAGE_PATH) and not ruleset_path.startswith(TEMP_STORAGE_PATH)) or ".." in ruleset_path or not re.search(r'^[a-z0-9\/\_\-\.]+$', ruleset_path, re.IGNORECASE):
                        delete_temp_files(job_id)
                        return render_template('/dalton/error.html', jid=jid, msg=["Invalid ruleset submitted: '%s'." % prod_ruleset_name, "Path/name invalid."])
                    elif not os.path.exists(ruleset_path):
                        delete_temp_files(job_id)
                        return render_template('/dalton/error.html', jid=jid, msg=["Ruleset does not exist on Dalton Controller: %s; ruleset-path: %s" % (prod_ruleset_name, ruleset_path)])
                    else:
                        # if these options are set, modify ruleset accordingly
                        if bEnableAllRules or bShowFlowbitAlerts:
                            modified_rules_path = "%s/%s_prod_modified.rules" % (TEMP_STORAGE_PATH, job_id)
                            regex = re.compile(r"^#+\s*(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s")
                            prod_rules_fh = open(ruleset_path, 'r')
                            modified_rules_fh = open(modified_rules_path, 'w')
                            for line in prod_rules_fh:
                                # if Enable disabled rules checked, do the needful
                                if bEnableAllRules:
                                    if regex.search(line):
                                        line = line.lstrip('# \t')
                                # if show all flowbit alerts set, strip out 'flowbits:noalert;'
                                if bShowFlowbitAlerts:
                                    line = re.sub(r'([\x3B\s])flowbits\s*\x3A\s*noalert\s*\x3B', '\g<1>', line)
                                modified_rules_fh.write(line)
                            prod_rules_fh.close()
                            modified_rules_fh.close()
                            ruleset_path = modified_rules_path
                        zf.write(ruleset_path, arcname=prod_ruleset_name)
                try:
                    if request.form.get('optionCustomRuleset') and request.form.get('custom_ruleset'):
                        zf.write(custom_rules_file, arcname='dalton-custom.rules')
                except:
                    logger.warn("Problem adding custom rules: %s", e)
                    pass
                vars_file = None
                if vars_file is not None:
                    zf.write(vars_file, arcname='variables.conf')
                if engine_conf_file:
                    zf.write(engine_conf_file, arcname=os.path.basename(engine_conf_file))

                #build the json job
                json_job = {}
                json_job['id'] = jid
                json_job['pcaps']= []
                if bSplitCap:
                    json_job['pcaps'].append(os.path.basename(splitcap['filename']))
                else:
                    for pcap in pcap_files:
                        json_job['pcaps'].append(os.path.basename(pcap['filename']))
                if engine_conf_file:
                    json_job['engine-conf'] = os.path.basename(engine_conf_file)
                json_job['user'] = user
                json_job['enable-all-rules'] = bEnableAllRules
                json_job['show-flowbit-alerts'] = bShowFlowbitAlerts
                json_job['custom-rules'] = bCustomRules
                json_job['track-performance'] = bTrackPerformance
                json_job['get-engine-stats'] = bGetEngineStats
                json_job['teapot-job'] = bteapotJob
                json_job['split-pcaps'] = bSplitCap
                json_job['use-suricatasc'] = bSuricataSC
                json_job['alert-detailed'] = bGetAlertDetailed
                json_job['get-fast-pattern'] = bGetFastPattern
                json_job['get-other-logs'] = bGetOtherLogs
                json_job['get-buffer-dumps'] = bGetBufferDumps
                json_job['sensor-tech'] = sensor_tech
                json_job['prod-ruleset'] = prod_ruleset_name
                json_job['override-external-net'] = bOverrideExternalNet
                json_job['suricata-eve'] = bGetEveLog
                json_job['zeek-json-logs'] = boptionZeekJSON
                # add var and other fields too
                str_job = json.dumps(json_job)

                #build the manifest file
                manifest_path = os.path.join(f"{TEMP_STORAGE_PATH}", f"{job_id}.json")
                f = open(manifest_path, 'w')
                f.write(str_job)
                f.close()

                zf.write(manifest_path, arcname='manifest.json')
            finally:
                zf.close()

            logger.debug("Dalton in page_coverage_summary(): created job zip file %s for user %s" % (zf_path, user))

            # Note: any redis sets here are not given expire times; these should
            # be set when job is requested by agent

            #store user name
            r.set("%s-user" % jid, user)

            #store sensor tech for job
            r.set("%s-tech" % jid, sensor_tech)

            # store submission time for job
            r.set("%s-submission_time" % jid, datetime.datetime.now().strftime("%b %d %H:%M:%S"))

            # if this is a teapot job,
            if bteapotJob:
                r.set("%s-teapotjob" % jid, bteapotJob)

            # set job as queued and write to the Redis queue
            set_job_status(jid, STAT_CODE_QUEUED)
            set_job_status_msg(jid, f"Queued Job {jid}")
            logger.info("Dalton user '%s' submitted Job %s to queue %s" % (user, jid, sensor_tech))
            r.rpush(sensor_tech, str_job)

            # add to list for queue web page
            r.lpush("recent_jobs", jid)

            if bSplitCap:
                splitcap_jid_list.append(jid)
            else:
                break

        #remove the temp files from local storage now that everything has been written to the zip file(s)
        delete_temp_files(job_id)

        if bteapotJob:
            if bSplitCap:
                return ','.join(splitcap_jid_list)
            else:
                return jid
        else:
            # make sure redirect is set to use http or https as appropriate
            if bSplitCap:
                # TODO: something better than just redirect to queue page
                rurl = url_for('dalton_blueprint.page_queue_default', _external=True)
            else:
                rurl = url_for('dalton_blueprint.page_show_job', jid=jid, _external=True)
            if rurl.startswith('http'):
                if "HTTP_X_FORWARDED_PROTO" in request.environ:
                    # if original request was https, make sure redirect uses https
                    rurl = rurl.replace('http', request.environ['HTTP_X_FORWARDED_PROTO'])
                else:
                    logger.warn("Could not find request.environ['HTTP_X_FORWARDED_PROTO']. Make sure the web server (proxy) is configured to send it.")
            else:
                # this shouldn't be the case with '_external=True' passed to url_for()
                logger.warn("URL does not start with 'http': %s" % rurl)
            return redirect(rurl)

@dalton_blueprint.route('/dalton/queue')
#@login_required()
def page_queue_default():
    """the default queue page"""
    global r
    num_jobs_to_show_default = 25

    # clear old job files from disk
    # spin off a thread in case deleting files from
    #  disk takes a while; this way we won't block the
    #  queue page from loading
    Thread(target=delete_old_job_files).start()

    try:
        num_jobs_to_show = int(request.args['numjobs'])
    except:
        num_jobs_to_show = num_jobs_to_show_default

    if not num_jobs_to_show or num_jobs_to_show < 0:
        num_jobs_to_show = num_jobs_to_show_default

    # use a list of dictionaries instead of a dict of dicts to preserve order when it gets passed to render_template
    queue = []
    queued_jobs = 0;
    running_jobs = 0;
    if r.exists('recent_jobs') and r.llen('recent_jobs') > 0:
        # get the last num_jobs_to_show jobs; can adjust if you want (default set above in exception handler)
        count = 0
        jobs = r.lrange("recent_jobs", 0, -1)
        for jid in jobs:
            # iterate thru all jobs and get total number of queued and running but only return 
            #  the most recent num_jobs_to_show jobs
            # do some cleanup on the list to remove jobs where the data has expired (been deleted).
            # Using 'jid-submission_time' and jid=status as tests -- if these don't exist the other keys associated
            # with that jid should be expired or will expire shortly.  That key gets set to expire
            # after a job is requested/sent to a sensor so we won't clear out queued jobs.
            if not r.exists("%s-submission_time" % jid) or not r.exists("%s-status" % jid):
                # job has expired
                logger.debug("Dalton in page_queue_default(): removing job: %s" % jid)
                r.lrem("recent_jobs", jid)
                # just in case, expire all keys associated with jid
                expire_all_keys(jid)
            else:
                status = int(get_job_status(jid))
                # ^^ have to cast as an int since it gets stored as a string (everything in redis is a string apparently....)
                #logger.debug("Dalton in page_queue_default(): Job %s, stat code: %d" % (jid, status))
                status_msg = "Unknown"
                if status == STAT_CODE_QUEUED:
                    status_msg = "Queued"
                    queued_jobs += 1
                elif status == STAT_CODE_RUNNING:
                    if check_for_timeout(jid):
                        status_msg = "Timeout"
                    else:
                        running_jobs += 1
                        status_msg = "Running"
                if count < num_jobs_to_show:
                    if status == STAT_CODE_DONE:
                        status_msg = "Complete"
                        if r.get("%s-error" % jid):
                            status_msg += " (Error)"
                        else:
                            status_msg += " (Success)"
                    elif status == STAT_CODE_INTERRUPTED:
                        status_msg = "Interrupted"
                    elif status == STAT_CODE_TIMEOUT:
                        status_msg = "Timeout"
                    # Note: could add logic to not show teapot jobs?; add if teapotjob: job['teapot'] = "True" else: "False"
                    job = {}
                    job['jid'] = jid
                    job ['tech'] = "%s" % r.get("%s-tech" % jid)
                    job['time'] = "%s" % r.get("%s-submission_time" % jid)
                    job['user'] = "%s" % r.get("%s-user" % jid)
                    job['status'] = status_msg
                    alert_count = get_alert_count(jid)
                    if status != STAT_CODE_DONE:
                        job['alert_count'] = '-'
                    elif alert_count is not None:
                        job['alert_count'] = alert_count
                    else:
                        job['alert_count'] = '?'
                    queue.append(job)
                count += 1
    return render_template('/dalton/queue.html', queue=queue, queued_jobs=queued_jobs, running_jobs=running_jobs, num_jobs=num_jobs_to_show)

@dalton_blueprint.route('/dalton/about')
#@login_required()
def page_about_default():
    """the about/help page"""
    return render_template('/dalton/about.html', page='')

#########################################
# API handling code (some of it)
#########################################

def controller_api_get_job_data(jid, requested_data):
    global r
    # add to as necessary
    valid_keys = ('alert', 'alert_detailed', 'ids', 'other_logs', 'eve',
                  'perf', 'tech', 'error', 'time', 'statcode', 'debug',
                  'status', 'submission_time', 'start_time', 'user', 'all',
                  'zeek_json'
                 )
    json_response = {'error':False, 'error_msg':None, 'data':None}
    # some input validation
    if not validate_jobid(jid):
        json_response["error"] = True
        json_response["error_msg"] = "Invalid Job ID value: %s" % jid
    elif not re.match(r'^[a-zA-Z\d\_\.\-]+$', requested_data):
        json_response["error"] = True
        json_response["error_msg"] = "Invalid request for data: %s" % requested_data
    else:
        try:
            status = get_job_status(jid)
        except:
            status = None
        if not status:
            # job doesn't exist
            # expire (delete) all keys related to the job just in case to prevent memory leaks
            expire_all_keys(jid)
            json_response["error"] = True
            json_response["error_msg"] = "Job ID %s does not exist" % jid
        else:
            # inspect the requested_data value and return the data
            # check 'valid_keys'
            if requested_data not in valid_keys:
                # check other_logs
                try:
                    ologs = r.get("%s-%s" % (jid, 'other_logs'))
                    if len(ologs) > 0:
                        ologs = json.loads(ologs)
                        for k in ologs.keys():
                            kkey = k.lower().strip()
                            kkey = kkey.replace(' ', '_')
                            if kkey == requested_data:
                                json_response["data"] = ologs[k]
                                break
                    if json_response["data"] is None:
                        json_response["error"] = True
                        json_response["error_msg"] = f"No data found for '{requested_data}' for Job ID {jid}"

                except Exception as e:
                    json_response["error"] = True
                    json_response["error_msg"] = "Unexpected error1: cannot pull '%s' data for Job ID %s" % (requested_data, jid)
                    logger.debug(f"{json_response['error_msg']}: {e}")
            else:
                ret_data = None
                if requested_data == "all":
                    # 'all' returns a structure of all data (other values just return a string)
                    ret_data = {}
                    try:
                        for key in valid_keys:
                            if key == "all":
                                continue
                            elif key == "other_logs":
                                # go thru other_logs struct and make each top-level entries in the response
                                ologs = r.get("%s-%s" % (jid, key))
                                if len(ologs) > 0:
                                    ologs = json.loads(ologs)
                                    for k in ologs.keys():
                                        kdata = ologs[k]
                                        k = k.lower().strip()
                                        k = k.replace(' ', '_')
                                        ret_data[k] = kdata
                            else:
                                ret_data[key] = r.get("%s-%s" % (jid, key))
                    except Exception as e:
                        json_response["error"] = True
                        json_response["error_msg"] = "Unexpected error: cannot pull '%s' data for Job ID %s" % (requested_data, jid)
                        logger.debug(f"{json_response['error_msg']}: {e}")
                else:
                    try:
                        ret_data = r.get("%s-%s" % (jid, requested_data))
                    except:
                        json_response["error"] = True
                        json_response["error_msg"] = "Unexpected error: cannot pull '%s' for jobid %s," % (requested_data, jid)
                    if requested_data == "other_logs" and len(ret_data) > 0:
                        ret_data = json.loads(ret_data)
                json_response["data"] = ret_data
    return json_response

@dalton_blueprint.route('/dalton/controller_api/v2/<jid>/<requested_data>', defaults={'raw': ''})
@dalton_blueprint.route('/dalton/controller_api/v2/<jid>/<requested_data>/<raw>', methods=['GET'])
#@auth_required()
def controller_api_get_request(jid, requested_data, raw):
    logger.debug(f"controller_api_get_request() called, raw: {'True' if raw == 'raw' else 'False'}")
    json_response = controller_api_get_job_data(jid=jid, requested_data=requested_data)
    if raw != 'raw' or json_response['error']:
        return Response(json.dumps(json_response), status=200, mimetype='application/json', headers = {'X-Dalton-Webapp':'OK'})
    else:
        filename = f"{jid}_{requested_data}"
        if requested_data in ["eve", "all"]:
            mimetype = "application/json"
            filename = f"{filename}.json"
        else:
            mimetype = "text/plain"
            filename = f"{filename}.txt"
        return Response(f"{json_response['data']}", status=200, mimetype=mimetype, headers = {'X-Dalton-Webapp':'OK', "Content-Disposition":f"attachment; filename={filename}"})

@dalton_blueprint.route('/dalton/controller_api/get-current-sensors/<engine>', methods=['GET'])
def controller_api_get_current_sensors(engine):
    """Returns a list of current active sensors"""
    global r, supported_engines
    sensors = []

    if engine is None or engine == '' or engine not in supported_engines:
        return Response("Invalid 'engine' supplied.  Must be one of %s.\nExample URI:\n\n/dalton/controller_api/get-current-sensors/suricata" % supported_engines, 
                        status=400, mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})

    # first, clean out old sensors
    clear_old_agents()

    # get active sensors based on engine
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            t = r.get("%s-tech" % sensor)
            if t.lower().startswith(engine.lower()):
                sensors.append(t)

    # sort so highest version number is first; ignore "rust_" prefix
    try:
        sensors.sort(key=lambda v:LooseVersion(prefix_strip(v.split('/', 1)[1], prefixes="rust_")), reverse=True)
    except Exception as e:
        try:
            sensors.sort(key=LooseVersion, reverse=True)
        except Exception as ee:
            sensors.sort(reverse=True)

    # return json
    json_response = {'sensor_tech': sensors}
    return Response(json.dumps(json_response), status=200, mimetype='application/json', headers = {'X-Dalton-Webapp':'OK'})

@dalton_blueprint.route('/dalton/controller_api/get-current-sensors-json-full', methods=['GET'])
def controller_api_get_current_sensors_json_full():
    """Returns json with details about all the current active sensors"""
    sensors = page_sensor_default(return_dict = True)
    return Response(json.dumps(sensors), status=200, mimetype='application/json', headers = {'X-Dalton-Webapp':'OK'})

@dalton_blueprint.route('/dalton/controller_api/get-max-pcap-files', methods=['GET'])
def controller_api_get_max_pcap_files():
    """Returns the config value of max_pcap_files (the number of
       pcap or compressed that can be uploaded per job).
       This could be useful for programmatic submissions where the
       submitter can ensure all the files will be processed.
    """
    return str(MAX_PCAP_FILES)

def parseZeekASCIILog(logtext):
    log = {}
    rows = []
    lines = logtext.splitlines()
    for line in lines:
        line = line.strip()
        if line.startswith('#'):
            if line.startswith('#separator'):
                separator = line.split()[1].encode().decode('unicode-escape')
            elif line.startswith('#fields'):
                log['fields'] = line.split(separator)[1:]
            elif line.startswith('#types'):
                log['types'] = line.split(separator)[1:]
            elif line.startswith('#close'):
                break
            else:
                continue
        else:
            rows.append(line.split(separator))

    log['rows'] = rows

    return log

