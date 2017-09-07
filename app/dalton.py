#!/usr/local/bin/python
"""
Dalton - a UI and management tool for submitting and viewing IDS jobs
"""

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
import sys
import shutil
from distutils.version import LooseVersion
import ConfigParser
import logging
from logging.handlers import RotatingFileHandler
import subprocess
from ruamel import yaml
import base64
import  cStringIO

# setup the dalton blueprint
dalton_blueprint = Blueprint('dalton_blueprint', __name__, template_folder='templates/dalton/')

# logging
file_handler = RotatingFileHandler('/var/log/dalton.log', 'a', 1 * 1024 * 1024, 10)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s'))
#file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
logger = logging.getLogger("dalton")
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

logger.info("Logging started")

try:
    dalton_config_filename = 'dalton.conf'
    dalton_config = ConfigParser.SafeConfigParser()
    dalton_config.read(dalton_config_filename)
    # user-configurable variables; see comments in dalton.conf for details.
    TEMP_STORAGE_PATH = dalton_config.get('dalton', 'temp_path')
    VARIABLES_STORAGE_PATH = dalton_config.get('dalton', 'var_path')
    RULESET_STORAGE_PATH = dalton_config.get('dalton', 'ruleset_path')
    JOB_STORAGE_PATH = dalton_config.get('dalton', 'job_path')
    CONF_STORAGE_PATH = dalton_config.get('dalton', 'engine_conf_path')
    REDIS_EXPIRE = int(dalton_config.get('dalton', 'redis_expire'))
    TEAPOT_REDIS_EXPIRE = int(dalton_config.get('dalton', 'teapot_redis_expire'))
    JOB_RUN_TIMEOUT = int(dalton_config.get('dalton', 'job_run_timeout'))
    REDIS_HOST = dalton_config.get('dalton', 'redis_host')
    API_KEYS = dalton_config.get('dalton', 'api_keys')
    MERGECAP_BINARY = dalton_config.get('dalton', 'mergecap_binary')
    U2_ANALYZER = dalton_config.get('dalton', 'u2_analyzer')
    DEBUG = dalton_config.getboolean('dalton', 'debug')
except Exception as e:
    logger.critical("Problem parsing config file '%s': %s" % (dalton_config_filename, e))

if DEBUG:
    file_handler.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)


if not MERGECAP_BINARY or not os.path.exists(MERGECAP_BINARY):
    logger.error("mergecap binary '%s'  not found.  Suricata jobs cannot contain more than one pcap." % MERGECAP_BINARY)
    MERGECAP_BINARY = None

if not os.path.exists(U2_ANALYZER):
    logger.error("U2 Analyzer '%s' not found.  Cannot process alert details." % U2_ANALYZER)
    U2_ANALYZER = None
if  U2_ANALYZER.endswith(".py"):
    # assumes 'python' binary in path
    U2_ANALYZER = "%s %s" % ("python", U2_ANALYZER)

#connect to the datastore
try:
    r = redis.Redis(REDIS_HOST)
except Exception as e:
    logger.critical("Problem connecting to Redis host '%s': %s" % (REDIS_HOST, e))

sensor_tech_re = re.compile(r"^[a-zA-Z0-9\x2D\x2E\x5F]+$")

#global values used by Flask
TRAP_BAD_REQUEST_KEY_ERRORS = True

#status codes
STAT_CODE_INVALID = -1
STAT_CODE_QUEUED = 0
STAT_CODE_RUNNING = 1
STAT_CODE_DONE = 2
STAT_CODE_INTERRUPTED = 3
STAT_CODE_TIMEOUT = 4

logger.info("Dalton Started.")

def delete_temp_files(job_id):
    """ deletes temp files for given job ID"""
    global TEMP_STORAGE_PATH
    if os.path.exists(TEMP_STORAGE_PATH):
        for file in glob.glob(os.path.join(TEMP_STORAGE_PATH, "%s*" % job_id)):
            if os.path.isfile(file):
                os.unlink(file)
    if os.path.exists("%s/%s" % (TEMP_STORAGE_PATH, job_id)):
        shutil.rmtree("%s/%s" % (TEMP_STORAGE_PATH, job_id))


def verify_temp_storage_path():
    """verify and create if necessary the temp location where we will store files (PCAPs, configs, etc.)
       when build a job zip file
    """
    global TEMP_STORAGE_PATH
    if not os.path.exists(TEMP_STORAGE_PATH):
        os.makedirs(TEMP_STORAGE_PATH)
    return True


def get_rulesets(engine=''):
    """ return a list of locally stored ruleset for jobs to use """
    global RULESET_STORAGE_PATH
    ruleset_list = []
    logger.debug("in get_rulesets(engine=%s)" % engine)
    # engine var should already be validated but just in case
    if not re.match("^[a-zA-Z0-9\_\-\.]*$", engine):
        logger.error("Invalid engine value '%s' in get_rulesets()" % engine)
        return ruleset_list
    ruleset_dir = os.path.join(RULESET_STORAGE_PATH, engine)
    if not os.path.isdir(ruleset_dir):
        logger.error("Could not find ruleset directory '%s'" % ruleset_dir)
        return ruleset_list
    file_list = os.listdir(ruleset_dir)
    # do we want to descend into directories?
    for file in file_list:
        if not os.path.isfile(os.path.join(ruleset_dir, file)):
            continue
        if  os.path.splitext(file)[1] == '.rules':
            # add full path or base or both?
            ruleset_list.append([file, os.path.join(ruleset_dir, file)])
    return ruleset_list


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
    global r
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
    global r
    return r.get("%s-statcode" % jobid)

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
        r.expire("%s-teapotjob" % jobid, EXPIRE_VALUE)
    except:
        pass


def expire_all_keys(jid):
    """expires (deletes) all keys for a give job ID"""
    # using the redis keys function ('r.keys("%s-*" % jid)') searches thru all keys which is not
    #   efficient for large key sets so we are deleting each one individually
    global r
    logger.debug("Dalton calling expire_all_keys() on job %s" % jid)
    keys_to_delete = ["ids", "perf", "alert", "alert_detailed", "other_logs", "error", "debug", "time", "statcode", "status", "start_time", "user", "tech", "submission_time", "teapotjob"]
    try:
        for cur_key in keys_to_delete:
            r.delete("%s-%s" % (jid, cur_key))
    except:
        pass


def check_for_timeout(jobid):
    """checks to see if a jobs has been running more than JOB_RUN_TIMEOUT seconds and sets it to STAT_CODE_TIMEOUT and sets keys to expire"""
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


@dalton_blueprint.route('/')
def index():
    return redirect('/dalton/')

@dalton_blueprint.route('/dalton')
@dalton_blueprint.route('/dalton/')
#@login_required()
def page_index():
    """the default homepage for Dalton"""
    return render_template('/dalton/index.html', page='')


@dalton_blueprint.route('/dalton/sensor_api/request_engine_conf/<sensor>', methods=['GET'])
#@auth_required()
def get_engine_conf_file(sensor):
    """ return the corresponding configuration file for passed in sensor (engine and version) 
        also returns the variables (stripped out from config)
    """
    # user's browser should be making request to dynamically update 'coverage' submission page
    try:
        conf_file = None
        vars_file = None
        (engine, version) = sensor.split('-', 1)
        epath = "%s/%s" % (CONF_STORAGE_PATH, engine)
        files = [f for f in os.listdir(epath) if os.path.isfile(os.path.join(epath, f))]
        found_files = []
        while len(found_files) == 0:
            for file in files:
                if file.startswith(sensor):
                    found_files.append(file)
            new_sensor = sensor.rsplit('.', 1)[0]
            if new_sensor == sensor:
                if sensor == engine:
                    break
                else:
                    sensor = engine
            else:
                sensor = new_sensor

        if len(found_files) > 0:
            # if multiple matches, get the one with the longest filename as that is assumed to be more specific
            conf_file = os.path.join(epath, sorted(found_files, key=lambda x: len(x))[0])

        engine_config = ''
        variables = ''

        if conf_file:
            # open, read, return
            # Unix newline is \n but for display on web page, \r\n is desired in some
            #  browsers/OSes.  Note: currently not converted back on job submit.
            fh = open(conf_file, 'rb')
            if engine.lower().startswith('suri'):
                # need the read() method to load the yaml
                contents = fh.read()
            else:
                # want to parse each line so put it in to a list
                contents = fh.readlines()
            fh.close()
            #  extract out variables
            if engine.lower().startswith('snort'):
                ignore_vars = ("RULE_PATH", "SO_RULE_PATH", "PREPROC_RULE_PATH", "WHITE_LIST_PATH", "BLACK_LIST_PATH")
                lines = iter(contents)
                while True:
                    try:
                        line = next(lines).rstrip('\r\n')
                        if not (line.startswith("var ") or line.startswith("portvar ") or line.startswith("ipvar ")):
                            engine_config += "%s\r\n" % line
                            # comment out (other) rule includes .. actually I don't want to do this here.
                            #  The engine config file is the place to do this.
                            #if line.startswith("include ") and line.endswith(".rules"):
                            #    engine_config += "#%s\r\n" % line
                            #else:
                            #    engine_config += "%s\r\n" % line
                        else:
                            if line.startswith("var ") and len([x for x in ignore_vars if x in line]) > 0:
                                engine_config += "%s\r\n" % line
                            else:
                                variables += "%s\r\n" % line
                    except StopIteration:
                        break
            elif engine.lower().startswith('suri'):
                # read in yaml with ruamel python lib, extract out vars
                # doing it like this adds a little load time but preserves
                # comments (for the most part). Can't use ruamel >= 0.15.x
                # b/c it won't preserve the inputted YAML 1.1 on dump (e.g.
                # quoted sexagesimals, unquoted 'yes', 'no', etc.
                logger.debug("Loading YAML for %s" % conf_file)
                # so apparently the default Suri config has what are interpreted
                #  as (unquoted) booleans and it uses yes/no. But if you change from
                #  yes/no to true/false, Suri will throw an error when parsing the YAML
                #  even though true/false are valid boolean valued for YAML 1.1.  ruamel.yaml
                #  will normalize unquoted booleans to true/false so quoting them here to
                #  preserve the yes/no.  This could/should? also be done on submission.
                contents = re.sub(r'(\w):\x20+(yes|no)([\x20\x0D\x0A\x23])', '\g<1>: "\g<2>"\g<3>', contents)
                # suri uses YAML 1.1
                config = yaml.round_trip_load(contents, version=(1,1), preserve_quotes=True)
                # pull out vars and dump
                variables = yaml.round_trip_dump({'vars': config.pop('vars', None)})
                # (depending on how you do it) the YAML verison gets added back
                # in when YAML of just vars is dumped.
                #  This data is concatenated with the rest of the config and there
                #  can't be multiple version directives. So just in case, strip it out.
                if variables.startswith("%YAML 1.1\n---\n"):
                    variables = variables[14:]
                # dump engine_config
                engine_config = yaml.round_trip_dump(config, version=(1,1), explicit_start=True)
            else:
                engine_config = '\r\n'.join([x.rstrip('\r\n') for x in contents])
                variables = ''
        else:
            logger.warn("No configuration file for sensor '%s'." % sensor)
            engine_config = "# No configuration file for sensor '%s'." % sensor
            variables = "# No variables in config for sensor '%s'." % sensor
        results = {'conf': engine_config, 'variables': variables}
        return json.dumps(results)

    except Exception, e:
        logger.error("Problem getting configuration file for sensor '%s'.  Error: %s" % (sensor, e))
        engine_config = "# Exception getting configuration file for sensor '%s'." % sensor
        variables = engine_config
        results = {'conf': engine_config, 'variables': variables}
        return json.dumps(results)

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


@dalton_blueprint.route('/dalton/sensor_api/request_job/<sensor_tech>/', methods=['GET'])
#@auth_required('read')
def sensor_request_job(sensor_tech):
    """Sensor API. Called when a sensor wants a new job"""
    # job request from Dalton Agent
    global r
    global STAT_CODE_RUNNING

    SENSOR_UID = 'unknown'
    try:
        SENSOR_UID = request.args['SENSOR_UID']
    except Exception, e:
        SENSOR_UID = 'unknown'

    SENSOR_IP = request.remote_addr

    AGENT_VERSION = 'unknown'
    try:
        AGENT_VERSION = request.args['AGENT_VERSION']
    except Exception, e:
        AGENT_VERSION = 'unknown'

    # update check-in data; use md5 hash of SENSOR_UID.SENSOR_IP
    # note: sensor keys are expired by function clear_old_agents() which removes the sensor
    # when it has not checked in in <x> amount of time (expire time configurable in that function).
    hash = hashlib.md5()
    hash.update(SENSOR_UID)
    hash.update(SENSOR_IP)
    SENSOR_HASH = hash.hexdigest()
    r.sadd("sensors", SENSOR_HASH)
    r.set("%s-uid" % SENSOR_HASH, SENSOR_UID)
    r.set("%s-ip" % SENSOR_HASH, SENSOR_IP)
    r.set("%s-time" % SENSOR_HASH, datetime.datetime.now().strftime("%b %d %H:%M:%S"))
    r.set("%s-epoch" % SENSOR_HASH, int(time.mktime(time.localtime())))
    r.set("%s-tech" % SENSOR_HASH, sensor_tech)
    r.set("%s-agent_version" % SENSOR_HASH, AGENT_VERSION)

    #grab a job! If it dosen't exist, return sleep.
    response = r.lpop(sensor_tech)
    if (response == None):
        return "sleep"
    else:
        respobj = json.loads(response)
        new_jobid = respobj['id']
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
        # if a user sees the "Running" message for more than a few seconds (depending on
        #   the size of the pcap(s)), then the job is hung on the agent or is going to
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
    global STAT_CODE_DONE, DALTON_URL, REDIS_EXPIRE, TEAPOT_REDIS_EXPIRE, TEMP_STORAGE_PATH
    global r

    jsons = request.form.get('json_data')
    result_obj = json.loads(jsons)

    set_job_status_msg(jobid, "Final Job Status: %s" % result_obj['status'])
    # get sensor hash and update ("%s-current_job" % SENSOR_HASH) with 'None'
    SENSOR_IP = request.remote_addr
    SENSOR_UID = 'unknown'
    try:
        SENSOR_UID = request.args['SENSOR_UID']
    except Exception, e:
        SENSOR_UID = 'unknown'
    hash = hashlib.md5()
    hash.update(SENSOR_UID)
    hash.update(SENSOR_IP)
    SENSOR_HASH = hash.hexdigest()
    r.set("%s-current_job" % SENSOR_HASH, None)
    r.expire("%s-current_job" % SENSOR_HASH, REDIS_EXPIRE)

    logger.debug("Dalton agent %s submitted results for job %s. Result: %s" % (SENSOR_UID, jobid, result_obj['status']))

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
            u2_file = os.path.join(TEMP_STORAGE_PATH, "unified2_%s_%s" % (jobid, SENSOR_HASH))
            u2_fh = open(u2_file, "wb")
            u2_fh.write(base64.b64decode(result_obj['alert_detailed']))
            u2_fh.close()
            u2spewfoo_command = "%s %s" % (U2_ANALYZER, u2_file)
            logger.debug("Processing unified2 data with command: '%s'" % u2spewfoo_command)
            alert_detailed = subprocess.Popen(u2spewfoo_command, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.read()
            # delete u2 file?
            #os.unlink(u2_file)
        except Exception as e:
            logger.error("Problem parsing unified2 data from Agent.  Error: %s" % e)
            alert_detailed = ""
    else:
        alert_detailed = ""
    # other_logs only supported on Suricata for now
    if "other_logs" in result_obj:
        other_logs = result_obj['other_logs']
    else:
        other_logs = ""

    r.set("%s-ids" % jobid, ids)
    r.set("%s-perf" % jobid, perf)
    r.set("%s-alert" % jobid, alert)
    r.set("%s-error" % jobid, error)
    r.set("%s-debug" % jobid, debug)
    r.set("%s-time" % jobid, time)
    r.set("%s-alert_detailed" % jobid, alert_detailed)
    r.set("%s-other_logs" % jobid, other_logs)
    set_keys_timeout(jobid)

    if error:
        set_job_status_msg(jobid, '<div style="color:red">ERROR!</div> <a href="/dalton/job/%s">Click here for details</a>' % jobid)
    else:
        set_job_status_msg(jobid, '<a href="/dalton/job/%s">Click here to view your results</a>' % jobid)

    set_job_status(jobid, STAT_CODE_DONE)
    return Response("OK", mimetype='text/plain', headers = {'X-Dalton-Webapp':'OK'})

@dalton_blueprint.route('/dalton/sensor_api/job_status/<jobid>', methods=['GET'])
#@login_required()
def get_ajax_job_status_msg(jobid):
    """return the job status msg (as a string)"""
    # user's browser requesting job status msg
    global STAT_CODE_RUNNING
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


@dalton_blueprint.route('/dalton/sensor_api/job_status_code/<jobid>', methods=['GET'])
#@login_required()
def get_ajax_job_status_code(jobid):
    """return the job status code (AS A STRING! -- you need to cast the return value as an int if you want to use it as an int)"""
    # user's browser requesting job status code
    global STAT_CODE_INVALID, STAT_CODE_RUNNING
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
    # user or agent requesting a job zip file
    global JOB_STORAGE_PATH
    # get the user (for logging)
    logger.debug("Dalton in sensor_get_job(): request for job zip file %s" % (id))
    path = "%s/%s.zip" % (JOB_STORAGE_PATH, id)
    if os.path.exists(path):
        filedata = open(path,'r').read()
        logger.debug("Dalton in sensor_get_job(): sending job zip file %s" % (id))
        return Response(filedata,mimetype="application/zip", headers={"Content-Disposition":"attachment;filename=%s.zip" % id})
    else:
        logger.error("Dalton in sensor_get_job(): could not find job %s at %s." % (id, path))
        return render_template('/dalton/error.html', jid=id, msg="Job %s does not exist on disk.  It is either invalid or has been deleted." % id)


def clear_old_agents():
    global r
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            minutes_ago = int(round((int(time.mktime(time.localtime())) - int(r.get("%s-epoch" % sensor))) / 60))
            # 7200 minutes == 5 days
#            if minutes_ago > 7200:
            if minutes_ago > 60:
                # delete old agents
                r.delete("%s-uid" % sensor)
                r.delete("%s-ip" % sensor)
                r.delete("%s-time" % sensor)
                r.delete("%s-epoch" % sensor)
                r.delete("%s-tech" % sensor)
                r.delete("%s-agent_version" % sensor)
                r.srem("sensors", sensor)


@dalton_blueprint.route('/dalton/sensor', methods=['GET'])
#@login_required()
def page_sensor_default():
    """the default sensor page"""
    global r
    sensors = {}
    # first clear out old agents ('sensors')
    clear_old_agents()
    if r.exists('sensors'):
        for sensor in r.smembers('sensors'):
            minutes_ago = int(round((int(time.mktime(time.localtime())) - int(r.get("%s-epoch" % sensor))) / 60))
            sensors[sensor] = {}
            sensors[sensor]['uid'] = "%s" % r.get("%s-uid" % sensor)
            sensors[sensor]['ip'] = "%s" % r.get("%s-ip" % sensor)
            sensors[sensor]['time'] = "%s (%d minutes ago)" % (r.get("%s-time" % sensor), minutes_ago)
            sensors[sensor]['tech'] = "%s" % r.get("%s-tech" % sensor)
            sensors[sensor]['agent_version'] = "%s" % r.get("%s-agent_version" % sensor)
    return render_template('/dalton/sensor.html', page='', sensors=sensors)

@dalton_blueprint.route('/dalton/coverage/<sensor_tech>/', methods=['GET'])
#@login_required()
def page_coverage_default(sensor_tech, error=None):
    """the default coverage wizard page"""
    global CONF_STORAGE_PATH
    global r
    #base_sensor_version = ''
    ruleset_dirs = []
    sensor_tech = sensor_tech.split('-')[0]
    conf_dir = "%s/%s" % (CONF_STORAGE_PATH, sensor_tech)
    if sensor_tech is None:
        return render_template('/dalton/error.html', jid='', msg="No Sensor technology selected for job.")
    elif not re.match("^[a-zA-Z0-9\_\-\.]+$", sensor_tech):
        return render_template('/dalton/error.html', jid='', msg="Invalid Sensor technology requested: %s" % sensor_tech)
    elif sensor_tech == 'summary':
        return render_template('/dalton/error.html', jid='', msg="Page expired.  Please resubmit your job or access it from the queue.")

    if not os.path.isdir(conf_dir):
        return render_template('/dalton/error.html', jid='', msg="No engine configuration directory for '%s' found (%s)." % (sensor_tech, conf_dir))


    # get list of rulesets based on engine
    rulesets = get_rulesets(sensor_tech.split('-')[0])

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
            except Exception, e:
                return render_template('/dalton/error.hml', jid=None, msg="Error getting sensor list for %s.  Error:\n%s" % (tech, e))
        try:
            # sort by version number
            sensors.sort(key=LooseVersion, reverse=True)
        except Exception as e:
            sensors.sort(reverse=True)

    # get conf or yaml file if sensor supports it
    engine_conf = None
    # return the engine.conf from the first sensor in the list which is sorted (see above)
    # and should be the most recent sensor version (depends on lexical sort done above). It 
    # is also the sensor version that is checked by default on the job submission page.
    # this also handles populating ip/port variables
    if len(sensors) > 0:
        try:
            configs = json.loads(get_engine_conf_file(sensors[0]))
            #logger.debug("CONfigs:\n%s" % configs)
            engine_conf = configs['conf']
            variables = configs['variables']
        except Exception as e:
            logger.error("Could not process JSON from get_engine_conf_file: %s" % e)
            engine_conf = "# not found"
            variables = "# not found"
    else:
        # no sensors available. Job won't run be we can provide a default engine.conf anyway
        engine_conf = "# not found"
        variables = "# not found"
    return render_template('/dalton/coverage.html', sensor_tech = sensor_tech,rulesets = rulesets, error=error, variables = variables, engine_conf = engine_conf, sensors=sensors)

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
        return render_template('/dalton/error.html', jid=jid, msg="Invalid Job ID. Job may have expired.  By default, jobs are only kept for %d seconds; teapot jobs are kept for %s seconds." % (REDIS_EXPIRE, TEAPOT_REDIS_EXPIRE))
    elif int(status) != STAT_CODE_DONE:
        # job is queued or running
        return render_template('/dalton/coverage-summary.html', page='', job_id=jid, tech=tech)
    else:
        # job exists and is done
        ids = r.get("%s-ids" % jid)
        perf = r.get("%s-perf" % jid)
        alert = r.get("%s-alert" % jid)
        error = r.get("%s-error" % jid)
        total_time = r.get("%s-time" % jid)
        alert_detailed = r.get("%s-alert_detailed" % jid)
        try:
            # this gets passed as json with log description as key and log contents as value
            # attempt to load it as json before we pass it to job.html
            other_logs = json.loads(r.get("%s-other_logs" % jid))
        except Exception, e:
            # if <jid>-other_logs is empty then error, "No JSON object could be decoded" will be thrown so just handling it cleanly
            other_logs = ""
            #logger.error("could not load json other_logs:\n%s\n\nvalue:\n%s" % (e,r.get("%s-other_logs" % jid)))

        # parse out custom rules option and pass it?
        custom_rules = False
        try:
            debug = r.get("%s-debug" % jid)
        except Exception, e:
            debug = ''
        overview = {}
        if (alert != None):
            overview['alert_count'] = alert.count('[**]') / 2
        else:
            overview['alert_count'] = 0
        if (error == ""):
            overview['status'] = 'Success'
        else:
            overview['status'] = 'Error'

        return render_template('/dalton/job.html', overview=overview,page = '', jobid = jid, ids=ids, perf=perf, alert=alert, error=error, debug=debug, total_time=total_time, tech=tech, custom_rules=custom_rules, alert_detailed=alert_detailed, other_logs=other_logs)

#  abstracting the job submission method away from the HTTP POST and creating this
#   function so that it can be called easier (e.g. from an API)
def submit_job():
    logger.debug("submit_job() called")
    # never finished coding this...

@dalton_blueprint.route('/dalton/coverage/summary', methods=['POST'])
#@auth_required()
# ^^ can change and add resource and group permissions if we want to restrict who can submit jobs
def page_coverage_summary():
    """ the summary page once the coverage wizard has been submitted"""
    # user submitting a job to Dalton via the web interface
    global JOB_STORAGE_PATH
    global TEMP_STORAGE_PATH
    global RULESET_STORAGE_PATH
    global r
    global STAT_CODE_QUEUED

    verify_temp_storage_path()
    digest = hashlib.md5()

    prod_ruleset_name = None

    # get the user who submitted the job .. not implemented
    user = "undefined"

    # grab the user submitted files from the web form (max number of arbitrary files allowed on the web form is 5)
    # note that these are file handle objects? have to get filename using .filename
    MAX_PCAP_FILES = 5
    form_pcap_files = []
    for i in range(MAX_PCAP_FILES):
        try:
            pcap_file = request.files['coverage-pcap%d' % i]
            if (pcap_file != None and pcap_file.filename != None and pcap_file.filename != '<fdopen>' and (len(pcap_file.filename) > 0) ):
                form_pcap_files.append(pcap_file)
                digest.update(pcap_file.filename)
        except:
            pass

    if len(form_pcap_files) == 0:
        #throw an error, no pcaps submitted
        return page_coverage_default(request.form.get('sensor_tech'),'You must specify a PCAP file.')
    elif (request.form.get('optionProdRuleset') == None and request.form.get('optionCustomRuleset') == None):
        #throw an error, no rules defined
        return page_coverage_default(request.form.get('sensor_tech'),'You must specify at least one ruleset.')
    else:
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
            logger.error("Dalton in page_coverage_summary(): Error: user %s submitted a job for invalid sensor tech, \'%s\'" % (user, sensor_tech))
            return render_template('/dalton/error.html', jid="<not_defined>", msg="There are no sensors that support sensor technology \'%s\'." % sensor_tech)

        #generate job_id based of pcap filenames and timestamp
        digest.update(str(datetime.datetime.now()))
        job_id = digest.hexdigest()[0:16]   #this is a temporary job id for the filename

        #store the pcaps offline temporarily
        # make temp job directory so there isn't a race condition if more
        #  than one person submits a pcap with the same filename at the same time
        if os.path.exists("%s/%s" % (TEMP_STORAGE_PATH, job_id)):
            shutil.rmtree("%s/%s" % (TEMP_STORAGE_PATH, job_id))
        os.makedirs("%s/%s" % (TEMP_STORAGE_PATH, job_id))

        pcap_files = []

        # process files from web form
        count = 0
        for pcap_file in form_pcap_files:
            filename = pcap_file.filename
            # do some input validation on the filename and try to do some accommodation to preserve original pcap filename
            filename = filename.replace(' ', '_')
            filename = filename.replace('\t', '_')
            filename = filename.replace('&', '_')
            filename = filename.replace('~', '_')
            if not re.match('^[a-zA-Z0-9\_\-\.]*$', filename):
                filename = 'coverage%d_%s.pcap' % (count, job_id)
            else:
                if not os.path.splitext(filename)[1] == '.pcap':
                    filename = "%s.pcap" % filename
            # handle duplicate filenames (e.g. same pcap sumbitted more than once)
            for pcap in pcap_files:
                if pcap['filename'] == filename:
                    filename = "%s_%s_%d.pcap" % (os.path.splitext(filename)[0], job_id, count)
                    break
            pcappath = os.path.join(TEMP_STORAGE_PATH, job_id, filename)
            count += 1
            pcap_files.append({'filename': filename, 'pcappath': pcappath})
            pcap_file.save(pcappath)

        # If multiple files submitted to Suricata, merge them here since
        #  Suricata can only read one file.
        if len(pcap_files) > 1:
            if not MERGECAP_BINARY:
                logger.error("No mergecap binary; unable to merge pcaps for Suricata job.")
                return render_template('/dalton/error.html', jid="<not_defined>", msg="No mergecap binary found on Dalton Controller.  Unable to process multiple pcaps for this Suricata job.")
            combined_file = "%s/combined-%s.pcap" % (os.path.join(TEMP_STORAGE_PATH, job_id), job_id)
            mergecap_command = "%s -w %s -F pcap %s" % (MERGECAP_BINARY, combined_file, ' '.join([p['pcappath'] for p in pcap_files]))
            logger.debug("Multiple pcap files sumitted to Suricata, combining the following into one file:  %s" % ', '.join([p['filename'] for p in pcap_files]))
            try:
                # validation on pcap filenames done above; otherwise OS command injeciton here
                mergecap_output = subprocess.Popen(mergecap_command, shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE).stdout.read()
                if len(mergecap_output) > 0:
                    # return error?
                    logger.error("Error merging pcaps with command:\n%s\n\nOutput:\n%s" % (mergecap_command, mergecap_output))
                    return render_template('/dalton/error.html', jid="<not_defined>", msg="Error merging pcaps with command:\n%s\n\nOutput:\n%s" % (mergecap_command, mergecap_output))
                pcap_files = [{'filename': os.path.basename(combined_file), 'pcappath': combined_file}]
            except Exception as e:
                logger.error("Could not merge pcaps.  Error: %s" % e)
                return render_template('/dalton/error.html', jid="<not_defined>", msg="Could not merge pcaps.  Error: %s" % e)

        # get enable all rules option
        bEnableAllRules = False
        if request.form.get('optionProdRuleset') and request.form.get('optionEnableAllRules'):
            bEnableAllRules = True

        # get showFlobitAlerts option
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
        #   functionality that programatically analyzes a rule and/or other situations
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
        #   This is only supported (for now) for agents that generage/process unified2 alerts
        #   and return pcap details from them.
        bGetAlertDetailed = False
        try:
            if request.form.get('optionAlertDetailed'):
                bGetAlertDetailed = True
        except:
            pass

        # get other logs (only supported in Suricata for now)
        bGetOtherLogs = False
        try:
            if request.form.get('optionOtherLogs'):
                bGetOtherLogs = True
        except:
            pass

        #get custom rules (if defined)
        bCustomRules = False
        custom_rules_file = os.path.join(TEMP_STORAGE_PATH, "%s_custom.rules" % job_id)
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
            fh = open(custom_rules_file, 'wb')
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
                    return page_coverage_default(request.form.get('sensor_tech'),"Invalid rule. Only ASCII characters are allowed in the literal representation of custom rules. Please encode necesary non-ASCII characters appropriately.  Rule:  %s" % line)
                # some rule validation for Snort and Suricata
                if sensor_tech.startswith('snort') or sensor_tech.startswith('suri'):
                    # rule must start with alert|log|pass|activate|dynamic|drop|reject|sdrop
                    if not re.search(r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop|event_filter|threshold|suppress|rate_filter|detection_filter)\s', line):
                        fh.close()
                        delete_temp_files(job_id)
                        return page_coverage_default(request.form.get('sensor_tech'),"Invalid rule, action (first word in rule) of \'%s\' not supported.  Rule: %s" % (line.split()[0], line))

                    # rule must end in closing parenthesis
                    if not line.endswith(')') and not line.startswith("event_filter") and not line.startswith("threshold") \
                        and not line.startswith("suppress") and not line.startswith("rate_filter") and not line.startswith("detection_filter"):
                        fh.close()
                        delete_temp_files(job_id)
                        return page_coverage_default(request.form.get('sensor_tech'),"Invalid rule, does not end with closing parenthesis.  Rule: %s" % line)

                    # last keyword in the rule must be terminated by a semicolon
                    if not line[:-1].rstrip().endswith(';') and not line.startswith("event_filter") and not line.startswith("threshold") \
                        and not line.startswith("suppress") and not line.startswith("rate_filter") and not line.startswith("detection_filter"):
                        fh.close()
                        delete_temp_files(job_id)
                        return page_coverage_default(request.form.get('sensor_tech'),"Invalid rule, last rule option must end with semicolon.  Rule:  %s" % line)

                    # add sid if not included
                    if not re.search(r'(\s|\x3B)sid\s*\:\s*\d+\s*\x3B', line) and not line.startswith("event_filter") and not line.startswith("threshold") \
                        and not line.startswith("suppress") and not line.startswith("rate_filter") and not line.startswith("detection_filter"):
                        # if no sid in rule, fix automatically instead of throwing an error
                        #return page_coverage_default(request.form.get('sensor_tech'),"\'sid\' not specified in rule, this will error.  Rule: %s" % line)
                        line = re.sub(r'\x29$', " sid:%d;)" % (sid_base + sid_offset), line)
                        sid_offset += 1
                # including newline because it was removed earlier with rstrip()
                fh.write("%s\n" % line)
            fh.close()

        if not sensor_tech:
            delete_temp_files(job_id)
            return render_template('/dalton/error.html', jid="<not_defined>", msg="Variable \'sensor_tech\' not specified.  Please reload the submission page and try again.")

        # get and write variables
        vars = request.form.get('custom_vars')
        if not vars:
            delete_temp_files(job_id)
            return page_coverage_default(request.form.get('sensor_tech'),"No variables defined.")

        conf_file = request.form.get('custom_engineconf')
        if not conf_file:
            delete_temp_files(job_id)
            return page_coverage_default(request.form.get('sensor_tech'),"No configuration file provided.")

        if sensor_tech.startswith('suri'):
            #yaml-punch!
            # combine engine conf and variables
            #ruamel!
            # set fast.log name?

            # set u2 naming

            # set filenes for output if other logs
        #  other_logs['Engine Stats'] = 'stats.log'
        #other_logs['Packet Stats'] = 'packet-stats.log'
        #if getOtherLogs:
        #    other_logs['Alert Debug'] = 'alert-debug.log'
        #    other_logs['HTTP Log'] = 'http.log'
        #    other_logs['TLS Log'] = 'tls.log'
        #    other_logs['DNS Log'] = 'dns.log'
        #    other_logs['EVE JSON'] = 'eve.json'
        #if getFastPattern:
        #    other_logs['Fast Pattern'] = 'rules_fast_pattern.txt'
        #if trackPerformance:
        #    other_logs['Keyword Perf'] = 'keyword-perf.log'

            # rules (default-rule-path and includes)
            # set suri_yaml_fh.write("default-rule-path: %s\n" % JOB_DIRECTORY) ?
            #suri_yaml_fh.write("rule-files:\n")
#        for rules_file in IDS_RULES_FILES:
#            suri_yaml_fh.write(" - %s\n" % rules_file)
#        suri_yaml_fh.close()
# include custom.rules

            # output to:
            #engine_conf_file = os.path.join(TEMP_STORAGE_PATH, "%s_suricata.yaml" % job_id)
        else:
            engine_conf_file = None
            if sensor_tech.startswith('snort'):
                vars_file = os.path.join(TEMP_STORAGE_PATH, "%s_variables.conf" % job_id)
                vars_fh = open(vars_file, "wb")

                for line in vars.split('\n'):
                    # strip out trailing whitespace (note: this removes the newline chars too so have to add them back when we write to file)
                    line = line.rstrip()
                    # strip out leading whitespace to make subsequent matching easier (snort won't complain about leading whitespace though)
                    line = line.lstrip()
                    # if empty or comment line, continue
                    if line == '' or re.search(r'^\s+$', line) or re.search(r'^#', line):
                        continue
                    if not re.search(r'^(var|portvar|ipvar)\s', line):
                        vars_fh.close()
                        delete_temp_files(job_id)
                        return page_coverage_default(request.form.get('sensor_tech'),"Invalid variable definition. Must be 'var', 'portvar', or 'ipvar': %s" % line)
                    vars_fh.write("%s\n" % line)
                engine_conf_file = os.path.join(TEMP_STORAGE_PATH, "%s_snort.conf" % job_id)
            else:
                engine_conf_file = os.path.join(TEMP_STORAGE_PATH, "%s_engine.conf" % job_id)
            engine_conf_fh = open(engine_conf_file, "wb")
            engine_conf_fh.write("%s" % request.form.get('custom_engineconf'))
            engine_conf_fh.close()

        # create jid (job identifier) value
        digest = hashlib.md5()
        digest.update(job_id)
        digest.update(sensor_tech)
        jid = digest.hexdigest()[0:16]

        #Create the job zipfile. This will contain the file 'manifest.json', which is also queued.
        #And place the rules file, variables file, and test PCAPs within the zip file
        if not os.path.exists(JOB_STORAGE_PATH):
            os.makedirs(JOB_STORAGE_PATH)
        zf_path = None
        if bteapotJob:
            # add 'teapot_' to the beginning of the jid to distinguish teapot jobs.  Among other things, this
            # makes it so cron or whatever can easily delete teapot jobs on a different schedule if need be.
            jid = 'teapot_%s' % jid
        zf_path = '%s/%s.zip' % (JOB_STORAGE_PATH, jid)
        zf = zipfile.ZipFile(zf_path, mode='w')
        try:
            for pcap in pcap_files:
                zf.write(pcap['pcappath'], arcname=os.path.basename(pcap['filename']))
            if request.form.get('optionProdRuleset'):
                ruleset_path = request.form.get('prod_ruleset')
                if not ruleset_path:
                    return render_template('/dalton/error.html', jid=jid, msg="No defined ruleset provided.")
                prod_ruleset_name = os.path.basename(ruleset_path)
                if not prod_ruleset_name.endswith(".rules"):
                    prod_ruleset_name = "%s.rules" % prod_ruleset_name
                logger.debug("ruleset_path = %s" % ruleset_path)
                logger.debug("Dalton in page_coverage_summary():\n    prod_ruleset_name: %s" % (prod_ruleset_name))
                if not ruleset_path.startswith(RULESET_STORAGE_PATH) or ".." in ruleset_path or not re.search(r'^[a-z0-9\/\_\-\.]+$', ruleset_path, re.IGNORECASE):
                    delete_temp_files(job_id)
                    return render_template('/dalton/error.html', jid=jid, msg="Invalid ruleset submitted: '%s'. Path/name invalid." % prod_ruleset_name)
                elif not os.path.exists(ruleset_path):
                    delete_temp_files(job_id)
                    return render_template('/dalton/error.html', jid=jid, msg="Ruleset does not exist on Dalton Controller: %s; ruleset-path: %s" % (prod_ruleset_name, ruleset_path))
                else:
                    # if these options are set, modify ruleset accordingly
                    if bEnableAllRules or bShowFlowbitAlerts:
                        modified_rules_path = "%s/%s_prod_modified.rules" % (TEMP_STORAGE_PATH, job_id)
                        ### begin superfluous code (see possible_negated_vars comment)
                        modified_vars_file = "%s/%s_variables_modified.conf" % (TEMP_STORAGE_PATH, job_id)
                        # not populated at the moment so most of the below code is
                        #  unnecessary.  (Enable flowbits rules code still used.)
                        possible_negated_vars = []
                        RFC_1918 = '[10.0.0.0/8,192.168.0.0/16,172.16.0.0/12]'

                        # load all variables into variables_dict dictionary
                        variables_dict = {}
                        if bEnableAllRules:
                            if sensor_tech.startswith('suri'):
                                # this is YAML; we could use some YAML libs to parse but probably overkill.
                                # Assumming at least 4 spaces before variable definitions
                                # TODO: think thru this a little more
                                regex = re.compile(r"^\s{4,}(?P<name>[^\x3A\x23]+)\x3A\s+[\x22\x27]?(?P<value>[^\x22\x27]+)")
                            else:
                                # can add other sensor formats with elif clauses
                                # this is for Snort:
                                regex = re.compile(r"^(ip)?var\s+(?P<name>[^\s]+)\s+(?P<value>.*)")

                            variables_fh = open(vars_file, 'rb')
                            for line in variables_fh:
                                if sensor_tech.startswith('snort'):
                                    line = line.lstrip()
                                result = regex.search(line)
                                if result:
                                    variables_dict[result.group('name')] = result.group('value')
                            variables_fh.close()

                        # disable some rules to prevent errors from !any rules;
                        # this is a simple hack although if you wanted you could parse all
                        # rules to identify !any situations but I don't think that is
                        # necessary at this point.
                        #
                        # do variable expansion on variables_dict
                        for var in variables_dict.keys():
                            original_var_value = variables_dict[var]
                            count = 0
                            while variables_dict[var][0] == '$':
                                newvar = variables_dict[var].lstrip('$')
                                # check to see if referenced variable is valid
                                if newvar in variables_dict:
                                    variables_dict[var] = variables_dict[newvar]
                                else:
                                    # referenced variable does not exist; reset value back to original and let engine throw the error
                                    variables_dict[var] = original_var_value
                                    break
                                count += 1
                                if count > 100:
                                    # variable loop (or overly long expansion) encountered; reset value back to original and let engine throw the error
                                    variables_dict[var] = original_var_value
                                    break

                        # Sometimes there are variables that are set to 'any' by default but are used
                        # in a negated context in the (disabled by default) ruleset.  Set those vars to RFC1918 if that is the case.
                        # Only do this if enable all rules is selected since !any rules should not be enabled in a default ruleset.
                        if bEnableAllRules:
                            vars_fh = open(vars_file, 'rb')
                            modified_vars_fh = open(modified_vars_file, 'wb')
                            for line in vars_fh:
                                for var in possible_negated_vars:
                                    if var in line and var in variables_dict and variables_dict[var] == 'any':
                                        if sensor_tech.startswith('suri'):
                                            regex = re.compile(r"^\s{4}" + re.escape(var) + r"\s*\x3A\s+[\x22\x27]?(?P<value>[^\x22\x27]+)")
                                        else:
                                            regex = re.compile(r"^(ip)?var\s+" + re.escape(var) + r"\s+(?P<value>.*)")
                                        result = regex.search(line)
                                        if result:
                                            value = result.group('value')
                                            new_line = re.sub(re.escape(value), RFC_1918, line, 1)
                                            line = new_line
                                            break
                                modified_vars_fh.write(line)
                            modified_vars_fh.close()
                            vars_fh.close()
                            vars_file = modified_vars_file
                        ### end superfluous code (see possible_negated_vars comment)


                        regex = re.compile(r"^#+\s*(alert|log|pass|activate|dynamic|drop|reject|sdrop)\s")
                        prod_rules_fh = open(ruleset_path, 'rb')
                        modified_rules_fh = open(modified_rules_path, 'wb')
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
                    zf.write(custom_rules_file, arcname='custom.rules')
            except:
                pass
            zf.write(vars_file, arcname='variables.conf')
            if engine_conf_file:
                zf.write(engine_conf_file, arcname=os.path.basename(engine_conf_file))

            #build the json job
            json_job = {}
            json_job['id'] = jid
            json_job['pcaps']= []
            for pcap in pcap_files:
                json_job['pcaps'].append(os.path.basename(pcap['filename']))
            json_job['user'] = user
            json_job['enable-all-rules'] = bEnableAllRules
            json_job['show-flowbit-alerts'] = bShowFlowbitAlerts
            json_job['custom-rules'] = bCustomRules
            json_job['track-performance'] = bTrackPerformance
            json_job['get-engine-stats'] = bGetEngineStats
            json_job['teapot-job'] = bteapotJob
            json_job['alert-detailed'] = bGetAlertDetailed
            json_job['get-fast-pattern'] = bGetFastPattern
            json_job['get-other-logs'] = bGetOtherLogs
            json_job['sensor-tech'] = sensor_tech
            json_job['prod-ruleset'] = prod_ruleset_name
            json_job['engine-conf'] = os.path.basename(engine_conf_file)
            # add var and other fields too
            str_job = json.dumps(json_job)

            #build the manifest file
            manifest_path = '%s/%s.json' % (TEMP_STORAGE_PATH, job_id)
            f = open(manifest_path, 'w')
            f.write(str_job)
            f.close()

            zf.write(manifest_path, arcname='manifest.json')
        finally:
            zf.close()

        logger.debug("Dalton in page_coverage_summary(): created job zip file %s for user %s" % (zf_path, user))

        #remove the temp files from local storage now that everything has been written to the zip file
        delete_temp_files(job_id)

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
        set_job_status_msg(jid, "Queued")
        logger.info("Dalton user '%s' submitted Job %s to queue %s" % (user, jid, sensor_tech))
        r.rpush(sensor_tech, str_job)

        # add to list for queue web page
        r.lpush("recent_jobs", jid)

        if bteapotJob:
            return jid
        else:
            return redirect('/dalton/job/%s' % jid)

@dalton_blueprint.route('/dalton/queue')
#@login_required()
def page_queue_default():
    """the default queue page"""
    global r
    num_jobs_to_show_default = 25

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
            # with that jid should be exipred or will expire shortly.  That key gets set to expire
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
                    queue.append(job)
                count += 1
    return render_template('/dalton/queue.html', queue=queue, queued_jobs=queued_jobs, running_jobs=running_jobs, num_jobs=num_jobs_to_show)

@dalton_blueprint.route('/dalton/about')
#@login_required()
def page_about_default():
    """the about/help page"""
    return render_template('/dalton/about.html', page='')

#########################################
# API handling code
#########################################

@dalton_blueprint.route('/dalton/controller_api/v2/<jid>/<requested_data>', methods=['GET'])
#@auth_required()
def controller_api_get_request(jid, requested_data):
    global r
    # add to as necessary
    valid_keys = ('alert', 'alert_detailed', 'ids', 'other_logs', 'perf', 'tech', 'error', 'time', 'statcode', 'debug', 'status', 'submission_time', 'start_time', 'user', 'all')
    json_response = {'error':False, 'error_msg':None, 'data':None}
    # some input validation
    if not re.match ('^(teapot_)?[a-zA-Z\d]+$', jid):
        json_response["error"] = True
        json_response["error_msg"] = "Invalid Job ID value: %s" % jid
    elif not re.match('^[a-zA-Z\d\_\.\-]+$', requested_data):
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
            # inspect the requested_data value and return the needful :)
            # check 'valid_keys'
            if requested_data not in valid_keys:
                json_response["error"] = True
                json_response["error_msg"] = "value '%s' invalid" % requested_data
            else:
                ret_data = None
                if requested_data == 'all':
                    # 'all' returns a dict of all data (other values just return a string)
                    ret_data = {}
                    try:
                        for key in valid_keys:
                            if key == 'all':
                                continue
                            else:
                                ret_data[key] = r.get("%s-%s" % (jid, key))
                    except:
                        json_response["error"] = True
                        json_response["error_msg"] = "Unexpected error: cannot pull '%s' data for Job ID %s" % (requested_data, jid)
                else:
                    try:
                        ret_data = r.get("%s-%s" % (jid, requested_data))
                    except:
                        json_response["error"] = True
                        json_response["error_msg"] = "Unexpected error: cannot pull '%s' for jobid %s," % (requested_data, jid)

                json_response["data"] = "%s" % ret_data

    return Response(json.dumps(json_response), status=200, mimetype='application/json', headers = {'X-Dalton-Webapp':'OK'})
    #print "raw response: %s" % json_response


