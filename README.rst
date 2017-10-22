======
Dalton
======

Dalton is a system that allows a user to quickly and easily run network
packet captures ("pcaps") against an intrusion detection system ("IDS")
sensor of his choice (e.g. Snort, Suricata) using defined rulesets
and/or bespoke rules.

Dalton also includes wizard-like web interface for
`Flowsynth <https://github.com/secureworks/flowsynth>`__ to facilitate
custom pcap creation.

**Quickstart**:

.. code:: bash

    start-dalton.sh

or this which does the same thing:

.. code:: text

    docker-compose build && docker-compose up -d

Then navigate to ``http://<docker-host>/dalton/``

To configure what sensors are available, see 
`Adding Sensors <#adding-sensors>`__.

Contents
========

-  `Use Cases <#use-cases>`__
-  `Design <#design>`__
-  `Requirements <#requirements>`__
-  `Installing and Running Dalton <#installing-and-running-dalton>`__
-  `Using Dalton <#using-dalton>`__

   -  `Launching A New Job <#launching-a-new-job>`__
   -  `Job Settings <#job-settings>`__
   -  `Config Files <#config-files>`__
   -  `Job Results <#job-results>`__
   -  `Job Queue <#job-queue>`__
   -  `Sensors <#sensors>`__

-  `Dalton API <#dalton-api>`__
-  `Teapot Jobs <#teapot-jobs>`__
-  `Adding Rulesets <#adding-rulesets>`__
-  `Adding Sensors <#adding-sensors>`__

   -  `Docker Sensors <#docker-sensors>`__
   -  `Non-Docker Sensors <#non-docker-sensors>`__
   
-  `Adding Sensor Configs <#adding-sensor-configs>`__
-  `Logging and Debugging <#logging-and-debugging>`__
-  `Flowsynth WebUI <#flowsynth-webui>`__
-  `Frequently Asked Questions <#frequently-asked-questions>`__
-  `Authors <#authors>`__

Use Cases
=========

These are the most common use cases for Dalton:

-  | **Testing Rulesets/Ruleset Coverage**
   | User-provided pcaps can be run thru an IDS engine loaded with a 
     particular ruleset.

-  | **Troubleshooting and Developing Signatures**
   | User-provided pcaps can be tested against user-provided ad-hoc IDS
     rules to quickly and easily see the IDS alerts and/or test for rule
     syntax errors.

-  | **Testing Variable Changes**
   | The ruleset variables used by the engine can easily be modified
     for submitted jobs; this can be used to determine the impact that a
     variable change may have on a specific detection.

-  | **Testing Configuration Changes**
   | Customized engine configuration files can included with submitted
     jobs; this can be used to determine the impact that an engine
     configuration change may have on a specific detection.

-  | **Testing specific IDS engine behavior**
   | Dalton supports the ability to apply the above use cases on
     specific sensors. The Dalton architecture is designed to accommodate
     and support sundry sensor engines and engine versions.

-  | **Crafting custom packet captures**
   | As part of the Web interface, Dalton has a module that provides a
     wizard-like web interface for Flowsynth. This allows for quick and
     easy network flow definition and pcap creation for popular protocols
     and traffic patterns.

Design
======

Dalton consists of a “controller” (dalton.py) and “agents”
(dalton-agent.py). The controller provides a web interface as well as a
HTTP API for agent communication and programmatic job results retrieval.
From a web interface, a user submits a job to be run on a particular
agent or agent platform. A Dalton job consists of one or more pcaps, a
pre-defined ruleset and/or custom rules, agent engine configuration
options (e.g. configuration to apply to Suricata when running a job),
and a manifest file specifying other options for the job (e.g. return
rule performance logs).

The Dalton Agent code (dalton-agent.py) runs on an IDS sensor and
provides an interface between the Dalton controller and an IDS engine.
Dalton agents grab pending jobs from the Dalton controller, run them
locally, and report the results back. These results are then displayed
in the web GUI provided by the Dalton controller. Jobs are submitted to
specific sensor engines (e.g. Suricata) and versions (e.g. 4.0.0).

Code for the Dalton agent and controller webapp are written in Python
and leverage `Flask <http://flask.pocoo.org/>`__ and
`Jinja2 <http://jinja.pocoo.org/>`__. On the Dalton controller,
`Redis <http://www.redis.io>`__ is used to manage the job queue, store
results, and maintain a list of active Dalton agents.

The Dalton controller includes a
`Flowsynth <https://github.com/secureworks/flowsynth>`__ WebUI module
that provides a user interface to assist with rapid Flowsynth language
prototyping and development of network flow definitions that are then
compiled into network pcaps by the Flowsynth script. This is basically a
GUI to facilitate input and output to Flowsynth. There is the option to
easily send Flowsynth WebUI generated pcaps to Dalton for testing.

While all the above systems could be independent physical (or virtual)
machines (and in fact this setup has been done), for ease of install and
use, everything has also been architected as a group of
`Docker <https://www.docker.com/>`__ containers. The Dalton codebase
includes Dockerfiles, “docker-compose.yaml”, and associated
configuration files to facilitate easy application launch using a set of
Docker containers.

Requirements
============

-  `Docker <https://www.docker.com/get-docker>`__
-  `Docker Compose <https://docs.docker.com/compose/install/>`__
-  Internet connection

Installing and Running Dalton
=============================

The easiest way to get Dalton up and running is to use the Docker files
provided and launch the system as a group of Docker containers. From
the root of the repository, run:

.. code:: bash

    start-dalton.sh

or this which does the same thing:

.. code:: bash

    docker-compose build && docker-compose up -d

To specify or add what agents (specific sensors and versions) are built
and run, edit the docker-compose.yml file as appropriate. See also
`Adding Sensors <#adding-sensors>`__.

The HTTP listen port can be changed if desired by editing the
``DALTON_EXTERNAL_PORT`` value in the .env file in the root of the
repository.

Configuration options for the Dalton Controller can be found in ``dalton.conf``; 
Configuration options for Dalton Agents can be found in 
``dalton-agent/dalton-agent.conf``.  See the inline comments in those files for 
more details.

Using Dalton
============

Launching A New Job
-------------------

The job submission page can be navigated to via the "New" menu on the
toolbar, or by clicking the ``[Go >>]`` button on the homepage below a given
sensor technology. The user will be prompted to select the sensor to be
used, supply a packet capture and ruleset (pre-defined and/or custom),
and given the ability to configure other options using the vertical
tab(s) on the submission page. On the 'Config Files' tab a user can
modify the sensor configuration file. The variables (e.g. $HTTP\_PORTS)
are split out from the rest of the config in the UI.

Please be aware that in most rulesets, almost all rules looking at TCP
traffic are set to inspect established sessions. This means that if a
pcap is supplied that only contains a single packet (e.g. from a sensor
or firewall technology that only logs a single packet), it will not
alert on these rules because the sensor will not see it as an
established session because of the lack of a TCP 3-way handshake. If
testing such a packet is desired, it will need to be incorporated into a
new pcap that includes a 3-way handshake and the server and client IPs
set correctly. This can be done fairly easily using Flowsynth; the
`Flowsynth Web UI <#flowsynth-webui>`__ makes this easy.

Job Settings
------------

On the job submission page, the "Job Settings" vertical tab provides a
number of user-configurable options:

-  | **Packet Captures**
   | Specify packet captures (libpcap format) to be run across the
     sensor. Depending on the engine, pcapng format may be supported as
     well. Archive files that contain pcaps can be submitted and the files
     will be extracted and used. Supported extensions (and their inferred
     formats) are .zip, .gz, .gzip, .bz2, .tar, .tgz, and .tar.gz. Since
     zip and tar files can contain multiple files, for those formats only
     members that have the ".pcap", ".pcapng", or ".cap" extensions will
     be included; the other files will be ignored.

-  | **Sensor Version**
   | The specific sensor version to use to run the specified pcap(s)
     and rule(s).

-  **Ruleset**

   -  | **Use a production ruleset**
      | Select which "production" (pre-defined) ruleset to use if this
        option is checked. See also `Adding
        Rulesets <#adding-rulesets>`__.

      -  | **Enable disabled rules**
         | Enable all disabled rules. This may cause engine errors if
           variables in disabled rules are not defined.
      -  | **Show all flowbit alerts**
         | Rules that have, "flowbit:noalert" will have that directive
           removed so that they show up in the sensor alerts.

   -  | **Use custom rules**
      | This allows a user to specify specific ad-hoc rules to include
        when testing the pcap(s). The user will need to ensure that any
        custom rules are valid since very little rule syntax validation is
        done on the Dalton controller; submitting invalid rules will
        result in verbose errors from the Dalton Agent (sensor engine)
        being used, which can facilitate rule syntax troubleshooting.

-  **Logs**

   -  | **Pcap records from alerts**
      | This tells the agent to process unified2 alert data and if alerts
        are generated by the job, this information will show up under the 
        "Alert Details" tab on the job results page. Information returned
        includes hex/ASCII output from packets that generated alerts as
        well as "Extra" data from the unified2 file such as "Original
        Client IP" from packets with "X-Forwared-For" or "True-Client-IP"
        HTTP headers (if enable\_xff is configured on the sensor).
   -  | **Other logs (Alert Debug, HTTP, TLS, DNS, etc.)**
      | *Suricata only*.  This will return other logs generated by the
        engine that can be useful for debugging. Depending on the version
        of Suricata running on the agent, some logs may not be supported.
        Currently the following logs are returned, each in it's own tab,
        and if the log file is empty, the tab won't be shown:

      -  | **Engine Stats** (*always returned even if this option is not
           checked*)
         | Statistics from the engine including numbers about memory,
           flows, sessions, reassembly, etc.
      -  | **Packet Stats** (*always returned even if this option is not
           checked*)
         | Statistics from the pcap including network protocols,
           application layer protocols, etc.
      -  | **Alert Debug**
         | Detailed information on what particular rules matched on for
           each alert.  Useful for seeing why an alert fired and/or
           troubleshooting false positives.
      -  | **HTTP Log**
         | A log of HTTP requests and responses, showing time, IPs and
           ports, HTTP method, URI, HTTP version, Host, User-Agent,
           Referer, response code, response size, etc.  By default, each
           line represents the HTTP request and response all in one.
      -  | **DNS Log**
         | A log of DNS requests and responses as provided by Suricata.
      -  | **TLS Log**
         | A log of SSL/TLS traffic as provided by Suricata.

   -  | **Rule profiling**
        Return per-rule performance statistics. This is data from the
        engine's rule performance profiling output. This data will show up
        under the "Performance" tab on the job results page.
   -  | **Fast pattern info**

      -  *Suricata only*. Return fast pattern data about the submitted
         rules.  The Dalton Suricata agent will return a file (displayed
         in the "Fast Pattern" tab) with details on what the engine is
         using for the fast pattern match.  To generate this, Suricata
         must do two runs – one to generate the fast pattern info and
         one to actually run the submitted job so this will approximately
         double the job run time. Unless fast pattern info is needed for
         some reason, there isn't a need to check this. Fast pattern
         data can be voluminous so it is not recommended that this be
         selected for a large production/pre-defined ruleset.

Config Files
------------

On the job submission page, the "Config Files" vertical tab provides the
ability to edit the configuration file(s) for the sensor:

-  | **Variables**
   |  The variables that can be used by the rules.

-  | **Configuration File**
   | The engine configuration file, minus rule the variables, that the
     Dalton agent uses for the job.

The variables and rest of the configuration file are separated
dynamically when the pages loads, or when a new sensor version is
selected. But on the disk the config is just one file in the
"engine-configs/" directory (e.g.
'engine-configs/suricata/suricata-4.0.0.yaml'). See also `Updating
Sensor Configs <#updating-sensor-configs>`__. 
When a job is submitted to the Controller, the ``Variables`` and
``Configuration File`` values will be combined in to a single file for a
Suricata Dalton agent job.

Job Results
===========

The job results page allows users to download the job zip file and also
presents the results from the job run in a tabulated interface:

-  | **Alerts**
     These are the raw alerts from the sensor.
-  | **Alert Details**
   | If ``Include Detailed Alerts`` is selected for a job, detailed output
     from processing unified2 alert files will be shown here.
-  | **IDS Engine**
   | This the raw output from the IDS engine. For Snort jobs, the engine
     statistics will be in this tab, at the bottom.
-  | **Performance**
   | If ``Enable rule profiling`` is enabled, those results will be
     included here.
-  | **Debug**
   | This is the Debug output from the agent.
-  | **Error**
   | If any errors are encountered by the Dalton agent running the job,
     they will be returned and displayed in this tab and the tab will be
     selected by default. If there are no errors, this tab will not be
     shown.
-  | **Other logs**
   | If other logs are returned by the agent they will each be displayed
     in their own tab if they are non-empty.  ``Engine Stats`` and ``Packet
     Stats`` are always returned for Suricata jobs.  See discussion in the
     above "Configuration Options" discussion for more details.

Job Queue
=========

Submitted jobs can be viewed on the "Queue" page. Each test is assigned
a quasi-unique sixteen byte Job ID, which is based on the job's runtime
parameters. Each recent Job ID is included on the 'Queue' page as a
hyperlink for easy access. Queued jobs will be cleared out periodically 
if an agent has not picked them up; this should not happen unless
all agents are down or are unreasonably backlogged.  There is additional
logic in the Dalton controller to respond appropriately when jobs have
timed out or have been interrupted; this should happen rarely, if ever.

Job results are cleared out periodically as well; this option is
configurable with the ``redis_expire`` parameter in the ``dalton.conf`` file.
`Teapot jobs <#teapot-jobs>`__ expire timeouts are 
configured with the ``teapot_redis_expire`` option.
After a job has completed, the original job can always be viewed (if it
hasn't expired) by accessing the following url::

  /dalton/job/<jobid>

A job zip file, which includes the packet capture file(s) submitted
along with rules and variables associated with the job, is stored on
disk, by default in the ``/opt/dalton/jobs`` directory; this location is
configurable via the ``job_path`` parameter in the ``dalton.conf`` file.
These files are cleaned up by Dalton based on the ``redis_expire`` and 
``teapot_redis_expire``.  Dalton only cleans up job zip files from disk when 
the ``Queue`` page is loaded.  To force the clean up job to run on demand, 
send a HTTP GET request to::

  /dalton/controller_api/delete-old-job-files

A job zip file can be accessed from the appropriate link on the job results 
page or directly downloaded using the following URL::

  /dalton/sensor_api/get_job/<jobid>.zip

Sensors
=======

Agents (a.k.a. "Sensors") check in to the Dalton server frequently
(about every second but configurable in the ``dalton-agent.conf`` file). The 
last time an agent checked in can be viewed on the ``Sensors`` page. Agents
that have not checked in recently will be pruned based on the 
``agent_purge_time`` value in the ``dalton.conf`` config file. When an
expired or new agent checks in to the Dalton Controller it will be
automatically (re)added and made available for job submissions.

Dalton API
==========

The Dalton controller provides a RESTful API to retrieve data about
submitted jobs.  API responses use JSON although the data returned in the values is, 
in most cases, just the raw text that is displayed in the Dalton web interface.
The API can be utilized via HTTP GET requests in this format::

  GET /dalton/controller_api/v2/<jobid>/<key>

Where ``<jobid>`` is the Job ID and::

    <key> : [alert|alert_detailed|all|debug|error|ids|other_logs|perf|start_time|statcode|status|submission_time|tech|time|user]

**Valid Keys**

-  **alert** - Alert data from the job. This is the same as what is
   displayed in the "Alerts" tab in the job results page.

-  **alert\_detailed** - Detailed alert data from the job. This is the
   same as what is displayed in the "Alert Details" tab in the job
   results page.

-  **all** - Returns data from all keys (except for "all" of course).

-  **debug** - Debug data from the job.  This is the same as what is
   displayed in the "Debug" tab in the job results page.

-  **error** - Error data from the job.  This is the same as what is
   displayed in the "Error" tab in the job results page.

-  **ids** - IDS Engine output from the job.  This is the same as what
   is displayed in the "IDS Engine" tab in the job results page.  
   For Snort Agents, engine statistics output at the end of the job 
   run are populated here.

-  **other\_logs** - Other logs from the job (Suricata only). 
   This is returned as key/value pairs with the key being the
   name of the log and the value being the contents of the log.

-  **perf** - Performance data from the job (if the job generated
   performance data).   This is the same as what is displayed in the
   "Performance" tab in the job results page.

-  **start\_time** - The time (epoch) the job was requested by a Dalton
   agent.  This is returned as a string.

-  **statcode** - Status code of the job.  This is a number returned as
   a string.  If a job doesn't exist, the API will return an error (see
   below) instead of an "Invalid" statcode.  Here is how to interpret
   the status code:

   +-------+-------------+
   | Code  |   Meaning   |
   +=======+=============+
   |  -1   |   Invalid   |
   +-------+-------------+
   |   0   |    Queued   |
   +-------+-------------+
   |   1   |   Running   |
   +-------+-------------+
   |   2   |     Done    |
   +-------+-------------+
   |   3   | Interrupted |
   +-------+-------------+
   |   4   |   Timeout   |
   +-------+-------------+

-  **status** - A string corresponding to the current status of a job. 
   This is used in the Dalton Controller web UI and is what is displayed
   in the browser when a job is submitted via the web interface to
   inform the user of the current progress/state of the job.  When a job
   is done, this will actually be a hyperlink saying "Click here to view
   your results".  Unless there is a specific use case, 'statcode' is 
   usually used instead of 'status' for determining the status of a job.

-  **submission\_time** - The time (formatted as "%b %d %H:%M:%S") the
   job was submitted to the Dalton Controller.

-  **tech** - The sensor technology (i.e. engine and version) the job was submitted
   for.  For example, 'suricata-4.0.0' is Suricata v4.0.0.  Suricata Agents
   start with "suricata-" and Snort Agents start with "snort-".

-  **time** - The time in seconds the job took to run, as reported by
   the Dalton Agent (this includes job download time by the agent). 
   This is returned as a string and is the same as the "Processing Time"
   displayed in the job results page.
-  **user** - The user who submitted the job. This will always be "undefined" 
   since authentication is not implemented in this release.

An API request returns JSON with three root elements:

-  | **name**
   | The requested data.   **All data is returned as a quoted string if it is
     not null**.  If the 'all' key is requested, this contains key/value
     pairs of all valid keys (so the JSON will need to be double-read to get
     to the data).  If the 'other\_logs' keyword is requested, this is
     key/value pairs the JSON will need to be double-read to get to the
     data or triple-read it if it is part of an 'all' request. This is null
     if there is no data for the requested key.

-  | **error**
   | [true\|false] depending if the API request generated an error. This is
     not returned as a quoted string.  \ **This** **indicates an error with
     the API request, not an error running the job**.  Errors running the job
     can be found by querying for the 'error' key (see above).

-  | **error_msg**
   | null if error is false, otherwise this is a quoted string with the error
     message.
 

**Examples:**

Request::

    GET /dalton/controller_api/v2/d1b3b838d41442f6/alert

Response:

.. code::

    {
    "data": "06/26/2017-12:08:13.255103  [**] [1:2023754:6] ET CURRENT_EVENTS 
            Malicious JS.Nemucod to PS Dropping PE Nov 14 M2 [**] [Classification: 
            A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.201:65430 
            -> 47.91.93.208:80\n\n06/26/2017-12:08:13.255103  [**] [1:2023882:2] 
            ET INFO HTTP Request to a *.top domain [**] [Classification: Potentially 
            Bad Traffic] [Priority: 2] {TCP} 192.168.1.201:65430 -> 47.91.93.208:80\n
            \n06/26/2017-12:08:13.646674  [**] [1:2023754:6] ET CURRENT_EVENTS 
            Malicious JS.Nemucod to PS Dropping PE Nov 14 M2 [**] [Classification: 
            A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.201:65430 
            -> 47.91.93.208:80\n\n06/26/2017-12:08:14.053075  [**] [1:2023754:6] ET 
            CURRENT_EVENTS Malicious JS.Nemucod to PS Dropping PE Nov 14 M2 [**] 
            [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 
            192.168.1.201:65430 -> 47.91.93.208:80\n\n06/26/2017-12:08:12.097144  
            [**] [1:2023883:1] ET DNS Query to a *.top domain - Likely Hostile 
            [**] [Classification: Potentially Bad Traffic] [Priority: 2] {UDP} 
            192.168.1.201:54947 -> 192.168.1.1:53\n\n",
    "error_msg": null,
    "error": false
    }

Request:

::

    GET /dalton/controller_api/v2/ae42737ab4f52862/ninjalevel

Response:

.. code:: javascript


    {"data": null, "error_msg": "value 'ninjalevel' invalid", "error": true}
 

Teapot Jobs
===========

Dalton has the concept and capability of what is called a "teapot" job. 
A teapot job is one that is short lived in the Redis database and
(usually) on disk.

Teapot jobs are useful when submitting large number of jobs and/or jobs
where the results are immediately processed and there isn't a need to
keep them around after that.  Often this is utilized in the programmatic
submission of jobs combined with using the `Dalton API <#dalton-api>`__
to automatically and/or quickly process the results.

Such job submissions are fleeting and voluminous in number.  In other 
words, short and stout.  *Like a little teapot.*

Teapot jobs differ from regular jobs in a few main ways:

-  Results kept for a shorter period of time than regular jobs. 
   Teapot job expire timeouts are  configured with the ``teapot_redis_expire`` 
   option in ``dalton.conf``.
-  Teapot jobs are submitted using the 'teapotJob' POST parameter (with
   any value).  This parameter is not set or available when submitting
   jobs via the Dalton web UI.
-  Teapot jobs have a job id ("JID") that starts with 'teapot\_'.
-  The submission of a teapot job results in the JID being returned
   instead of a redirect page.

Currently, if teapot jobs have not expired, they will show up in the Dalton
Queue in the web UI although it would be fairly trivial to change the code to
exclude them from the list.

Adding Rulesets
===============

For each Dalton job, a single 'defined ruleset' file can be used and/or 'custom rules'. 
Custom rules are entered in the Web UI but defined rulesets are stored on disk.

On the Dalton Controller, defined rulesets must be in the directory 
specified by the ``ruleset_path`` variable in ``dalton.conf``.  By default this is  
``/opt/dalton/rulesets``.  Inside that directory there must be a ``suricata`` 
directory where Suricata rules must be placed and a ``snort`` directory where 
Snort rules must be placed.  The ruleset files must end in
``.rules``.

If the default ``ruleset_path`` value is not changed from 
``/opt/dalton/rulesets`` then the ``rulesets`` directory 
(and subdirectories) on the host running the Dalton 
Controller container is shared with the container so '.rules' files can be easily 
added from the host machine.

Popular open source rule download and management tools such as 
`rulecat <https://github.com/jasonish/py-idstools>`__ and 
`PulledPork <https://github.com/shirkdog/pulledpork>`__ make it trivial to download
rulesets, combine all rules into a single ``.rules`` file, and then store it 
in the necessary location.

The Dalton Controller container includes rulecat (see the ``rulecat_script`` variable 
in ``dalton.conf``) and when the Dalton Controller first starts up, if there 
are no existing rulesets, it will attempt to download the latest Suricata and Snort rulesets 
from `rules.emergingthreats.net <https://rules.emergingthreats.net>`__.

Adding Sensors
==============

Adding sensors to Dalton is a farily simple process.  If there isn't already 
a corresponding or compatible configuration file for the new sensor, that 
will also need to be added; see `Adding Sensor Configs <#adding-sensor-configs>`__.

It is possible and often desirable to have multiple sensors of the same type 
(e.g. Suricata 4.0.1), all running jobs.  In that case, just set the ``SENSOR_TECHNOLOGY`` 
value the same (e.g. 'suricata-4.0.1') and they will all request jobs that 
have been submitted to that queue.  A single job is given to only one sensor 
so whichever Agent requests the next job in the queue first get it.

Docker Sensors
--------------
The ``docker-compose.yml`` file includes directives to build Dalton Agents for
a variety of Suricata and Snort versions.  The sensor engines (Suricata or
Snort) are built from source.  To add a new or different version, just copy 
one of the existing specifications and change the version number(s) as necessary.

For example, here is the specification for Suricata 3.2.3:

.. code:: yaml

      agent-suricata-3.2.3:
        build:
          context: ./dalton-agent
          dockerfile: Dockerfiles/Dockerfile_suricata
          args:
            - SURI_VERSION=3.2.3
        image: suricata-3.2.3:latest
        container_name: suricata-3.2.3
        environment:
          - AGENT_DEBUG=${AGENT_DEBUG}
        restart: always

To add a specification for Suricata 4.0.2 (if it exists) just change the
SURI_VERSION arg value from '3.2.3' to '4.0.2'.  The other places the version is used here
('image', 'container_name', etc.) are there to provide useful labels for 
easier management of the Dalton Agent containers.  Example Suricata 4.0.2
specification:

.. code:: yaml

      agent-suricata-4.0.2:
        build:
          context: ./dalton-agent
          dockerfile: Dockerfiles/Dockerfile_suricata
          args:
            - SURI_VERSION=4.0.2
        image: suricata-4.0.2:latest
        container_name: suricata-4.0.2
        environment:
          - AGENT_DEBUG=${AGENT_DEBUG}
        restart: always
        
Suricata can also have ``SURI_VERSION=current`` in which case the latest 
Suricata version will be used to build the Agent.  Having a 'current' Suricata 
version specification in the ``docker-compose.yml`` file is especially convenient 
since when a new version comes out, all that has to be done is run the
``start-dalton.sh`` script and a new Dalton Agent with the latest Suricata 
version will be built and available.

Snort agents are the same way but the args to customize are ``SNORT_VERSION`` and 
(if changed) ``DAQ_VERSION``.  Example Snort specification:

.. code:: yaml

      # Snort 2.9.11 from source
        agent-snort-2.9.11:
          build:
            context: ./dalton-agent
            dockerfile: Dockerfiles/Dockerfile_snort
            args:
              - SNORT_VERSION=2.9.11
              - DAQ_VERSION=2.0.6
          image: snort-2.9.11:latest
          container_name: snort-2.9.11
          environment:
            - AGENT_DEBUG=${AGENT_DEBUG}
          restart: always

Suricata agents should build off the suricata Dockerfile -- 
``Dockerfiles/Dockerfile_suricata``; and Snort agents should build off the 
Snort Dockerfile at ``Dockerfiles/Dockerfile_snort``.

Non-Docker Sensors
------------------
Sensors don't have to be Docker containers or part of the docker-compose
network to be used by the Dalton Controller; they just have to be able to 
access and talk with the Docker Controller webserver.

A Suricata or Snort machine can be turned into a Dalton Agent fairly easily. 
Requirements:

-  Engine (Suricata or Snort)
-  Python
-  ``dalton-agent.py``
-  ``dalton-agent.conf``

The ``dalton-agent.conf`` file must be modified to point to the Docker 
Controller (see ``DALTON_API`` option).  Additionally, if the 
``SENSOR_TECHNOLOGY`` value is not set to 'auto' (or automatic version 
determination fails), the the ``SENSOR_TECHNOLOGY`` value should be 
set and must follow a certain
pattern; it should start with the engine name ('suricata' or 'snort'), 
followed by a dash followed by the version number. For example:  'suricata-4.0.1'.  
This format helps tell the Dalton Controller what technology is being used as 
well as maps back to the config files on the Controller.  Technically the version 
number part of the ``SENSOR_TECHNOLOGY`` string can be arbitrary but in that 
case a configuration file with the corresponding name should be present on the 
Dalton Controller so it knows which configuration file to load and use for jobs 
related to that sensor.

For more details on the Dalton Agent configuration options, see the inline 
comments in the ``dalton-agent.py`` file.

To start the Dalton Agent, run dalton-agent.py::
        
        Usage: dalton-agent.py [options]

        Options:
        -h, --help            show this help message and exit
        -c CONFIGFILE, --config=CONFIGFILE
                              path to config file [default: dalton-agent.conf]


Adding Sensor Configs
=====================

Sensor configuration files (e.g. ``suricata.yaml`` or ``snort.conf``) are 
stored on the Dalton Controller.  When a sensor checks in to the Controller, 
it is registered in Redis and when that sensor is selected for a Dalton job, 
the corresponding config file is loaded, populated under the ``Config Files`` vertical tab 
in the Web UI, and submitted with the Dalton job.

The Dalton Controller uses the ``engine_conf_path`` variable from ``dalton.conf`` 
to use as a starting location on the filesystem to find sensor configuration files to use.  
Inside that directory there must be 
a ``suricata`` directory where the Suricata ``.yaml`` files go and a ``snort`` 
directory where the Snort ``.conf`` files go.

By default, on the Controller, ``engine_conf_path`` is set to ``/opt/dalton/app/static/engine-configs`` 
which is symlinked from ``/opt/dalton/engine-configs``.  The Dalton Controller and host also 
share the ``engine-configs`` directory to make it easy to add config files as needed 
from the host.

It is recommended that the ``engine_conf_path`` not be changed since Flask looks in 
the ``static`` directory to serve the config files and changing it will 
mostly like break something.

Sensor configuration files 
are not automatically added when Agents are build or the Controller is run; 
they must be manually added. 
However, the Dalton Controller already comes with the default (from source) config files 
for Suricata versions 0.8.1 thru 4.0.1 and for Snort 2.9.0 thru 2.9.11. 
Duplicate config files are not included.  For example, since all the Suricata 
1.4.x versions have the same (default) .yaml file, only "suricata-1.4.yaml" 
is included.

The Controller picks the config file to load/use based off the sensor technology 
(Suricata or Snort) and Agent supplied version number, both of which are part 
of the ``SENSOR_TECHNOLOGY`` string submitted by the Agent which should start 
with "snort-" or "suricata-", depending on the engine type.  The "version 
number" is just the part of the string after "suricata-" or "snort-".

So if a sensor identifies itself as "suricata-5.9.1" then the Controller will 
look for a file with the name "suricata-5.9.1.yaml" in the 
``engine-configs/suricata/`` directory.  If it can't find an 
exact match, it will attempt to find the closest match it can based off the
version number.  The version number is just used to help map an Agent 
to a config.  So, for example, if an Agent identified itself as 
"suricata-mycustomwhatever" and there was a corresponding 
"suricata-mycustomwhatever.yaml" file in ``engine-configs/suricata``, 
it would work fine.


For new Suricata releases, the ``.yaml`` file from source should just 
be added to the ``engine-configs/suricata`` directory and named 
appropriately.  For new Snort releases, it is recommended that the 
default ``.conf`` file be run thru  the ``clean_snort_config.py`` 
script located in the ``engine-configs/`` directory::

    Usage:
    
    python clean_snort_config.py <in-file> <out-file>



Logging and Debugging
=====================

By default, the Dalton Controller logs to ``/var/log/dalton.log`` and Dalton 
Agents log to ``/var/log/dalton-agent.log``.  The nginx container logs to 
the ``/var/log/nginx`` directory (``dalton-access.log`` and 
``dalton-error.log``).  The (frequent) polling that Dalton Agents do to the 
nginx container to check for new jobs is intentionally not logged since it is 
considered too noisy.

For the Dalton Controller, debugging can be enabled in ``dalton.conf`` file or 
by setting the ``CONTROLLER_DEBUG`` environment variable (e.g. 
``CONTROLLER_DEBUG=1``.  This can also be passed during the container build 
process and set in the ``.env`` file.  If either the config file or environment 
variable has debugging set, debug logging will be enabled.

For the Dalton Controller, debugging can be enabled in ``dalton-agent.conf`` file or 
by setting the ``AGENT_DEBUG`` environment variable (e.g. 
``AGENT_DEBUG=1``.  This can also be passed during the container build 
process and set in the ``.env`` file.  If either the config file or environment 
variable has debugging set, debug logging will be enabled.

Flowsynth WebUI
===============

Dalton included a Web UI for 
`Flowsynth <https://github.com/secureworks/flowsynth>`__ , a tool that 
facilitates network packet capture creation. ... 

TODO


Frequently Asked Questions
==========================

1. | **Why is it named 'Dalton'?**
   | Dalton is the name of Patrick Swayze's character in the movie 
     "Road House".

#. | **How do I configure the Dalton Controller to listen on a different port?**
   | The external listen port of the Dalton Controller can be set in the ``.env``
     file in the repository root.  The Dalton Controller and nginx containers
     must be rebuilt for the change to take effect (just run ``start_dalton.sh``).

#. | **Is SSL/TLS supported?**
   | The default configuration does not leverage SSL nor is there a simple
     "on/off" switch for SSL/TLS.  However, if you know what you are doing, it
     isn't difficult to configure nginx for it and point the Dalton Agents to
     it.  This has been done in some environments.
   
#. | **Will this work on Windows?**
   | The native Dalton code won't work as expected on Windows without non-trivial 
     code changes. 
     However, if the Linux containers can run on Windows, then 
     it should be possible to get containers working on a Windows host.  But
     this has not been tested.
   
#. | **Is there Dalton Agent support for Snort < v2.9.1?**
   | Currently no.  Dalton Agents that run Snort utilize the 'dump' DAQ to replay pcaps
     and DAQ wasn't introduced until Snort 2.9.  Dalton Agents for older Snort
     versions (e.g. 2.4) have been written in the past but are not part of this 
     open source release.  However, if there is a demand for such support, then
     adding support for older Snort versions will be reconsidered.

#. | **Are other sensor engines supported such as Bro?**
   | No; currenlty only Suricata and Snort are supported.

#. | **Does Dalton support authentication such as username/password/API tokens or 
     authorization enforcement like discretionary access control?**
   | No, not in this open source release although such additions have been done
     before, including single sign on integration.  However, such enhancements 
     would require non-trivial code additions. There are some authentication 
     decorators commented out and scattered throughout the code and the Dalton 
     Agents do send and API token as part of their requests but the Dalton 
     Controller doesn't validate them.  The lack of authentication and 
     authorization does mean that it isn't difficult for malicious actors to 
     flood the Controller, submit malformed jobs, corrupt job results, dequeue
     jobs, and DoS the application.
     
#. | **How can I programmatically submit a job to Dalton?**
   | Right now, a programmatic submission must mimic a Web UI submission. In the
     future, a more streamlined and easier to use submission API may be exposed.
     Feel free to submit a pull request with this feature.

#. | **Why is it that when I try to build a Snort 2.9.0 or 2.9.0.x container, it fails when
     configuring Snort saying it can't find the 'dnet' files?**
   | Attempting to build Snort 2.9.0 and 2.9.0.x  will fail because 
     Autoconf can't find the dnet files. This was apparently fixed in 
     Snort > 2.9.1. If 
     you really want a Snort 2.9.0 or 2.9.0.x Agent, you will have to build 
     one out yourself.  The Dalton Agent code should work
     fine on it.  If it turns out that there is a lot of demand for 
     Snort 2.9.0.x Agents, adding native support for it will be reconsidered.

#. | **Regarding the code ... why did you do that like that? What were you 
     thinking? Do you even know about object-oriented programming?**
   | These are valid questions.  Much of the code was written many years ago 
     when the author was new to Python, never having written any Python code
     before other than tweaking a few lines of code in existing projects, and
     unaware of Python's object-oriented support.  While such code could be
     cleaned up and refactored, a lot of it was left as-is since it already 
     worked and it was decided that time and effort should be spent elsewhere.
     Additionally, the Dalton Agent code was originally written to run on 
     restricted/custom systems that only had Python 2.4 support and couldn't use 
     non-standard libraries.  This is especially noticeable (painful?) with 
     the use of urllib2 instead of urllib3 or Requests.  Therefore, if you 
     do review the code, it is reqeusted that you approach it with a spirit of
     charity.

#. | **I found a bug in Dalton.  What should I do?**
   | Feel free to report it and/or fix it and submit a pull request.
   
 

Authors
=======

-  David Wharton
   
-  Will Urbanski
   

Feedback including bug reports, suggestions, improvements, questions,
etc. is welcome.

 