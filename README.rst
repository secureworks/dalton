======
Dalton
======

Dalton is a system that allows a user to quickly and easily run network
packet captures ("pcaps") against an intrusion detection system ("IDS")
sensor of his choice (e.g. Snort, Suricata) using defined rulesets
and/or bespoke rules.

Dalton also includes a wizard-like web interface for
`Flowsynth <https://github.com/secureworks/flowsynth>`__ to facilitate
custom pcap creation.

.. image:: app/static/images/dalton.png

**Quickstart**:

.. code:: bash

    ./start-dalton.sh

or this which does the same thing:

.. code:: text

    docker-compose build && docker-compose up -d

Then navigate to ``http://<docker-host>/dalton/``

To configure what rulesets are available, see 
`Adding Rulesets <#adding-rulesets>`__.

To configure what sensors are available, see 
`Adding Sensors <#adding-sensors>`__.

If Dalton is being built behind a proxy, see
`Building Behind A Proxy <#building-behind-a-proxy>`__

Contents
========

-  `Use Cases <#use-cases>`__
-  `Design <#design>`__
-  `Requirements <#requirements>`__
-  `Installing and Running Dalton <#installing-and-running-dalton>`__

   -  `Building Behind A Proxy <#building-behind-a-proxy>`__

-  `Using Dalton <#using-dalton>`__

   -  `Launching A New Job <#launching-a-new-job>`__
   -  `Suricata Socket Control Mode <#suricata-socket-control-mode>`__
   -  `Job Settings <#job-settings>`__
   -  `Config Files <#config-files>`__
   -  `Job Results <#job-results>`__
   -  `Job Queue <#job-queue>`__
   -  `Sensors <#sensors>`__

-  `Dalton API <#dalton-api>`__

   -  `Job API <#job-api>`__
   -  `Controller API <#controller-api>`__

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
   | User-provided pcaps can be tested against user-provided ad hoc IDS
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
-  Internet connection (to build)

Installing and Running Dalton
=============================

The easiest way to get Dalton up and running is to use the Docker files
provided and launch the system as a group of Docker containers. From
the root of the repository, run:

.. code:: bash

    ./start-dalton.sh

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


Building Behind A Proxy
-----------------------

It is recognized that getting systems to work behind a corporate proxy can be an endless source of
acute frustration and ongoing consternation.  However, a small attempt
has been made to make it easier for Dalton to be built behind a proxy. Note that
it comes with no guarantees.

To build Dalton behind a proxy, most likely Docker and
the containers will need to be set up to use the proxy.

Configuring Docker to use a proxy will vary depending on the platform
Docker is run on.  For Linux, it usually involves editing the
``/etc/default/docker`` file, or if systemd is used (as it is in Ubuntu 16.04),
see `https://docs.docker.com/engine/admin/systemd/ <https://docs.docker.com/engine/admin/systemd/>`__.
This is for *Docker*, not the
Docker containers.  This allows Docker to do things like pull (external) images
from the Docker Hub Registry.

To build the Dalton containers behind a proxy, edit the ``.env`` file
in the Dalton repository root and set the ``http_proxy``, ``https_proxy``, and/or ``no_proxy``
variables accordingly.  Example:

.. code:: bash

    http_proxy=http://192.168.1.50:3128
    https_proxy=http://192.168.1.50:3128
    no_proxy=

Be aware that DNS may not work in which case the IP of the
proxy will need to be used.

These environment variables will be used when containers are
*built*.  This will allow the container to do things like
'apt-get install...'; they are used *inside* the container,
not by docker to pull (external) images.

Note that these environment variables do not persist after the
container is built.  This means that if there are no rulesets,
and Dalton attempts to download default rulesets, it will most
likely fail and result in an empty file.  In this case rulesets
will need to be added (and the empty files removed);
see `Adding Rulesets <#adding-rulesets>`__.

Enabling SSL/TLS on the Controller
----------------------------------
The Dalton Controller web interface supports SSL/TLS.  To enable,
set the ``DALTON_EXTERNAL_PORT_SSL`` variable in the ``.env`` file
to the desired SSL/TLS listen port; by default it is 443.  Then,
modify the "nginx" section of the ``docker-compose.yml`` and uncomment
(or add if it is missing) the line:

.. code:: bash

             - DALTON_EXTERNAL_PORT_SSL=${DALTON_EXTERNAL_PORT_SSL}

The Dalton Controller comes with a default certificate and key but
these should be replaced.  The certificate and key files should be
placed in the ``nginx-conf/tls/`` directory and named ``dalton.crt``
and ``dalton.key``, respectively.


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
modify the sensor configuration file.

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

Suricata Socket Control Mode
----------------------------

Dalton Agents running Suricata 3.0 and later are capable of using the
`Suricata Socket Control <https://suricata.readthedocs.io/en/latest/manpages/suricatasc.html>`__
mode to process pcaps instead of starting up a new Suricata process for each job
and using pcap replay mode.  Leveraging the socket control feature of Suricata
offers significant job performance gains (reduced job runtime) when the
ruleset and config do not change between jobs on an agent, since the overhead
of starting up Suricata and processing the ruleset is eliminated.

To enable Suricata Socket Control select ``Use Suricata Socket Control Pcap Processing Mode``
on the job submission page, located in the ``Sensor Version`` section of the ``Job Settings``
vertical tab.

If the Dalton agent is unable to use Suricata Socket Control for a job, it will
use the classic read pcap mode.

If ``Rule profiling`` is enabled, then Suricata Socket Control
mode will be disabled for that job since the rule profiling and
keyword profiling logs do not get populated (or usually do not have
enough time to be populated) for socket control pcap runs.

The Suricata Socket Control mode leverages the ``suricatasc`` Python
module included with the Suricata source.  If the agent was built
as a Docker container using the Dockerfile(s) provided, then the
``suricatasc`` Python file(s) should already be there and the
agent aware of them.  If not, or if the module is not in PYTHONPATH,
then the ``SURICATA_SC_PYTHON_MODULE`` config item in the
``dalton-agent.conf`` file can be set to point to correct location.

While Socket Control is supported by Suricata in versions 1.4 and later,
the ``suricatasc`` module was not Python 3 compatible until Suricata
3.0 so that is the earliest version Dalton supports.

-  | **Problems with Suricata Socket Control Mode**
   | There are some known issues with Suricata Socket Control, not related to Dalton.
     If problems are encountered
     with it, try running the job with this option disabled.

   -  | **Sample Issues**
      | `Docker Suricata Socket Control crashing using command 'reopen-log-files <https://redmine.openinfosecfoundation.org/issues/3436>`__

      | `Suricata 4.1 Seg Fault: Socket Control pcap-file and corrupt pcap <https://redmine.openinfosecfoundation.org/issues/3448>`__

      | `Alert metadata not present in EVE output when using Socket Control Pcap Processing Mode <https://redmine.openinfosecfoundation.org/issues/3467>`__

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
     be included; the other files will be ignored. Password protected zip
     files will be attempted to be decrypted with the passsword 'infected'.

   | If multiple pcaps are submitted for a Suricata job, they will be 
     combined into a single pcap on job submission since (older versions of) Suricata can
     only read a single pcap in read pcap mode.

   -  | **Create separate jobs for each pcap**
      | If selected, each pcap file sumitted (or found in an archive) will be
        submitted as its own job.  When all the jobs are submitted, Dalton will
        redirect the user to the Queue page.  If this is a `Teapot job <#teapot-jobs>`__,
        then a comma separated list of JIDs is returned.

-  | **Sensor Version**
   | The specific sensor version to use to run the specified pcap(s)
     and rule(s).

   -  | **Use Suricata Socket Control Pcap Processing Mode**
      | See `Suricata Socket Control Mode <#suricata-socket-control-mode>`__ section.

-  **Ruleset**

   -  | **Use a production ruleset**
      | Select which "production" (pre-defined) ruleset to use if this
        option is checked. See also `Adding
        Rulesets <#adding-rulesets>`__.

      -  | **Enable disabled rules**
         | Enable all disabled rules. This may cause engine errors if
           variables in disabled rules are not defined.
      -  | **Show all flowbit alerts**
         | Rules that have, ``flowbit:noalert`` will have that directive
           removed so that they show up in the sensor alerts.

   -  | **Use custom rules**
      | This allows a user to specify specific ad hoc rules to include
        when testing the pcap(s). The user will need to ensure that any
        custom rules are valid since very little rule syntax validation is
        done on the Dalton controller; submitting invalid rules will
        result in verbose errors from the Dalton Agent (sensor engine)
        being used, which can facilitate rule syntax troubleshooting.
        Custom rules are added to a ``dalton-custom.rules`` file and included in the job
        so valid format is supported such as multiple rules (one on
        each line), and comments (ignored lines) beginning with a pound
        ('#') sign. If a ``sid`` is not provided for a custom rule, one will be added
        when the job is submitted.

-  **Logs**

   -  | **Pcap records from alerts (unified2)**
      | This tells the agent to process unified2 alert data and if alerts
        are generated by the job, this information will show up under the 
        "Alert Details" tab on the job results page. Information returned
        includes hex/ASCII output from packets that generated alerts as
        well as "Extra" data from the unified2 file such as "Original
        Client IP" from packets with "X-Forwared-For" or "True-Client-IP"
        HTTP headers (if enable\_xff is configured on the sensor).
        Note that Suricata version 6 and later does not support unified2
        output so this option is unavailable for jobs to such agents.
   -  | **EVE Log**
      | *Suricata only*, version 2 and later.  Turn on (or off, if not checked)
        EVE logging and return the results.
        The specific EVE log types, settings, etc. are determined by
        (and can be set in) the config file.
        Since Suricata version < 3.1
        doesn't support multiple TLS loggers, TLS logging in the EVE log
        is disabled for jobs submitted to such agents.
        The maximum supported
        size for the EVE log is 512MB; see note about 512MB limit for
        'Other logs'.
   -  | **Other logs (Alert Debug, HTTP, TLS, DNS, etc.)**
      | *Suricata only*.  This will return other logs generated by the
        engine that can be useful for analysis and debugging.
        Depending on the version
        of Suricata running on the agent, some logs may not be supported.
        Like all results, the 'Other logs' data is stored in Redis as a
        string and the maximum size this can be is 512MB. If these logs
        exceed that size, there may be data loss and/or other issues.
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
           This won't be available if Suricata is compiled with Rust support
           or if the version of Suricata is 5.0 or later.
      -  | **TLS Log**
         | A log of SSL/TLS traffic as provided by Suricata.
   -  | **Dump buffers (alerts only)**
      | This will display the contents of buffers used by the detection
        engines, which can be useful for troubleshooting signature creation with traffic
        that may not be parsing as expected. Since such output can be voluminous,
        only buffer content associated with alerts are returned.  To see buffer content from
        more traffic, use rule(s) that match on more traffic (or even
        a generic rule that matches on all traffic).
        Snort will output buffer contents into a "Buffer Dump" log output.
        Suricata works differently and will place contents into "HTTP Buffers",
        "TLS Buffers" and/or "DNS Buffers". These are Lua script outputs
        intended to be visually similar than the Snort buffer dump output.
        However on Suricata the protocol must be specified for the buffer dump
        to work. Examples: ``alert http``, ``alert tls``, ``alert dns``.
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

-  | **Configuration File**
   | The engine configuration file, including variables, that the
     Dalton agent uses for the job.

If the ``Override EXTERNAL_NET (set to 'any')`` option is selected
(on by default), then the ``EXTERNAL_NET`` IP variable will be set to
``any`` when the job is submitted.

See also `Updating Sensor Configs <#updating-sensor-configs>`__. 

Job Results
===========

The job results page allows users to download the job zip file and also
presents the results from the job run in a tabulated interface:

-  | **Alerts**
     These are the raw alerts from the sensor.
-  | **Alert Details**
   | If ``Include Detailed Alerts`` is selected for a job, detailed output
     from processing unified2 alert files will be shown here.
-  | **EVE JSON** (Suricata only)
   | The EVE log, with syntax highlighting, if EVE logging is enabled.
     The ``Format`` checkbox
     "pretty-prints" the EVE data; the ``Dark Mode`` checkbox applies
     a dark mode theme/coloring to the EVE data.  The UI also dynamically
     presents checkboxes based on the event types present in the EVE log.
     These can be used to filter the displayed EVE data.
     If the EVE data is more than 2000000 bytes, then by default the
     ``Dark Mode`` option is
     disabled and syntax coloring is turned off, for performance reasons.
-  | **IDS Engine**
   | This the raw output from the IDS engine. For Snort jobs, the engine
     statistics will be in this tab, at the bottom.
-  | **Performance**
   | If ``Rule profiling`` is enabled, those results will be
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
``teapot_redis_expire``. Visiting a job's share link increases the expire
time for the job zip file. How long the expire time is extended can be
configured in the ``dalton.conf`` file as well with the ``share_expire``
configuration option. Dalton only cleans up job zip files from disk when the
``Queue`` page is loaded. To force the clean up job to run on demand, send
a HTTP GET request to::

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

Job API
-------

The Dalton controller provides a RESTful API to retrieve data about
submitted jobs.  API responses use JSON or the raw ("RAW") data, and
the data returned in the values is, 
in most cases, just the raw text that is displayed in the Dalton web interface.

**JSON API**

The JSON API can be utilized via HTTP GET requests in this format::

  GET /dalton/controller_api/v2/<jobid>/<key>

For requests, ``<jobid>`` is the Job ID and::

    <key> : [alert|alert_debug|alert_detailed|all|debug|dns_log|
             error|engine_stats|eve|fast_pattern|http_log|ids|
             keyword_perf|other_logs|packet_stats|perf|start_time|
             statcode|status|submission_time|tech|time|tls_log|user]

A JSON API request returns JSON with three root elements:

-  | **data**
   | The requested data.  If the key is invalid for the
     job, then an error is returned, along with an error message stating
     as such. If there is no data for the requested Job ID and key, then
     this ``data`` parameter value is an empty string and ``error`` is set
     to false..

-  | **error**
   | [true\|false] depending if the API request generated an error. This is
     not returned as a quoted string.  \ **This** **indicates an error with
     the API request, not an error running the job**.  Errors running the job
     can be found by querying for the 'error' key (see above).

-  | **error_msg**
   | null if error is false, otherwise this is a quoted string with the error
     message.

**RAW API**

The RAW API can be utilized via the same HTTP GET requests appended with "/raw"::

  GET /dalton/controller_api/v2/<jobid>/<key>/raw

The ``<jobid>`` and ``<key>`` are the same as the JSON API but a
RAW API request returns the raw data from the Redis database, in the response body.
This is basically what is returned from the JSON API but not encapsulated or encoded as JSON.  For
RAW API responses, the Content-Type header is set to "text/plain" with the exception of
the "eve" and "all" logs which
use "application/json".  A RAW request for the "all" key returns a string representation
of a Python dictionary with all the key-value pairs.
The RAW responses also include "attachment" and "filename"
in the Content-Disposition header that prompt browsers to download/save the file.

**Valid Keys**

-  **alert** - Alert data from the job. This is the same as what is
   displayed in the "Alerts" tab in the job results page.

-  **alert\_debug** - A full alert log containing much information for
   signature writers or for investigating suspected false positives (Suricata only).
   This is the same as what is displayed in the "Alert Debug" tab in the job
   results page.

-  **alert\_detailed** - Detailed alert data from the job. This is the
   same as what is displayed in the "Alert Details" tab in the job
   results page.

-  **all** - Returns data from all keys (except for "all" of course).

-  **debug** - Debug data from the job.  This is the same as what is
   displayed in the "Debug" tab in the job results page.

-  **dns\_log** - A line based log of DNS requests and responses (Suricata only).
   This is the same as what is displayed in the "DNS Log" tab in the job
   results page.

-  **engine\_stats** - Contains data from various counters of the Suricata
   engine (Suricata only).  This is the same as what is displayed in
   the "Engine Stats" tab in the job results page.

-  **error** - Error data from the job.  This is the same as what is
   displayed in the "Error" tab in the job results page.

-  **eve** - EVE JSON output from the job (Suricata only).  This is the same as what is
   displayed in the "EVE JSON" tab in the job results page.

-  **fast\_pattern** - Fast pattern details for the submitted rules (Suricata only).
   This is the same as what is displayed in the "Fast Pattern" tab in the job
   results page.

-  **http\_log** - A line based log of HTTP requests (Suricata only).  This is the
   same as what is displayed in the "HTTP Log" tab in the job results page.

-  **ids** - IDS Engine output from the job.  This is the same as what
   is displayed in the "IDS Engine" tab in the job results page.  
   For Snort Agents, engine statistics output at the end of the job 
   run are populated here.

-  **keyword\_perf** - Contains data of per keyword profiling (Suricata only).
   This is the same as what is displayed in the "Keyword Perf" tab in the job
   results page.

-  **other\_logs** - *deprecated* - Other logs from the job (Suricata only).
   This is returned as key/value pairs with the key being the
   name of the log and the value being the contents of the log. This key
   is deprecated and is not included in the ``all`` key response. The contents
   of ``other_logs``, e.g. "http_log", "tls_log", etc., can and should be
   accessed directly.

-  **packet\_stats** - Statistics from the pcap(s) (Suricata only).  This is the
   same as what is displayed in the "Engine Stats" tab in the job results page.

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
   for, in the format ``<engine>/<version>``.
   For example, ``suricata/4.0.0`` is Suricata v4.0.0.
   If a custom config is used, it will be added on the end, also separated by a
   forward slash.  For example, ``suricata/4.0.7/mycustomconfigname``.  A Suricata 4
   sensor compiled with Rust support will have "rust\_" prepended to the version,
   for example, ``suricata/rust_4.1.5``.

-  **time** - The time in seconds the job took to run, as reported by
   the Dalton Agent (this includes job download time by the agent). 
   This is returned as a string and is the same as the "Processing Time"
   displayed in the job results page.

-  **tls\_log** - A line based log of TLS handshake parameters (Suricata only).
   This is the same as what is displayed in the "TLS Log" tab in the job
   results page.

-  **user** - The user who submitted the job. This will always be "undefined" 
   since authentication is not implemented in this release.

**Examples:**

JSON API Request::

    GET /dalton/controller_api/v2/d1b3b838d41442f6/alert

JSON API Response:

.. code::

    {
    "data": "06/26/2017-12:08:13.255103  [**] [1:180043530:4] Nemucod Downloader
            Trojan Request Outbound [**] [Classification: 
            A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.201:65430 
            -> 47.91.93.208:80\n\n06/26/2017-12:08:13.255103  [**] [1:180056733:3] 
            Suspicious HTTP Request to a *.top TLD - Outbound [**] [Classification: Potentially 
            Bad Traffic] [Priority: 2] {TCP} 192.168.1.201:65430 -> 47.91.93.208:80\n
            \n06/26/2017-12:08:13.646674  [**] [1:180043530:4] Nemucod Downloader
            Trojan Request Outbound [**] [**] [Classification: 
            A Network Trojan was detected] [Priority: 1] {TCP} 192.168.1.201:65430 
            -> 47.91.93.208:80\n\n",
    "error_msg": null,
    "error": false
    }

JSON API Request::

    GET /dalton/controller_api/v2/ae42737ab4f52862/ninjalevel

JSON API Response:

.. code:: javascript

    {"data": null, "error_msg": "No data found for 'ninjalevel' for Job ID ae42737ab4f52862", "error": true}

RAW API Request::

    GET /dalton/controller_api/v2/ae42737ab4f52862/alert/raw

RAW API Response:

.. code::

    12/16/2019-20:03:24.094114  [**] [1:806421601:0] MyMalware C2 Request Outbound [**]
    [Classification: (null)] [Priority: 3] {TCP} 192.168.102.203:45661 -> 172.16.31.41:80

Controller API
--------------

In addition to providing information on submitted jobs, the Dalton API includes
the ability to pull information from, and perform limited actions on, the Controller.
The following routes can be accessed via HTTP GET requests.  Full examples are not
provided here but can be easily obtained by making the request in a web browser.

-  | **/dalton/controller_api/request_engine_conf?sensor=<sensor>**
   | Returns the requested configuration file as text.  The <sensor> value
     is going to be the engine, version, and, if applicable, the custom config
     filename, separated by forward slashes.  For example:
     ``suricata/5.0.0`` or ``suricata/5.0.0/mycustomconfig.yaml``.
     Suricata version 4.x compiled with Rust support will have
     the prefix "rust\_" before the version, e.g. ``suricata/rust_4.1.5``.

   | If no exact match is found for a config file on disk, the closest file
     that matches is returned.

-  | **/dalton/controller_api/delete-old-job-files**
   | Deletes old job files from disk. Returns the number of
     files deleted.
     For more info see the `Job Queue <#job-queue>`__ section.

-  | **/dalton/controller_api/job_status/<jobid>**
   | Returns a string corresponding to the current status of a job.
     This is used by the web browser primarily when a job is running.
     See the 'status' key information in
     the `Job API <#job-api>`__ section.

-  | **/dalton/controller_api/job_status_code/<jobid>**
   | Returns the job status code for the given jobid.
     This is the job status code number, returned as string.

   | For more details, see the information about 'statcode' in
     the `Job API <#job-api>`__ section.

-  | **/dalton/controller_api/get-current-sensors/<engine>**
   | Returns a JSON response with 'sensor_tech' as the root element containing
     an array of current active sensors, sorted descending based on ruleset
     filename (just like the list in the web interface).

   | <engine> should be ``suricata``, ``snort``, or ``zeek``.

   | Example response:

.. code:: javascript

    {"sensor_tech": ["suricata/4.0.1", "suricata/3.2.4", "suricata/2.0.9"]}

-  | **/dalton/controller_api/get-current-sensors-json-full**
   | Response is a JSON payload with details about
     all the current active sensors (agents). Info includes agent IP,
     last check-in time, tech (e.g. ``suricata/4.0.1``), etc.

-  | **/dalton/controller_api/get-prod-rulesets/<engine>**
   | Returns a list of current available production rulesets on the
     Controller for the given engine. The list contains the full path of
     the rules files on the Controller.

   | <engine> should be ``suricata`` or ``snort``

   | Example response:

.. code:: javascript

    {"prod-rulesets": [
        "/opt/dalton/rulesets/suricata/SCWX-20171024-suricata-security.rules",
        "/opt/dalton/rulesets/suricata/SCWX-20171024-suricata-malware.rules",
        "/opt/dalton/rulesets/suricata/ET-20171023-all-suricata.rules"
        ]
    }

-  | **/dalton/controller_api/get-max-pcap-files**
   | Returns the maximum number of pcap (or archive) files the controller is configured
     to process per job submission.  This is set by the ``max_pcap_files`` option
     in dalton.conf and knowing this can be useful to ensure that all pcaps programmatically
     submitted are going to be processed.
     A single archive file, even though it can contain multiple
     pcaps, is only considered a single file in this context.

-  | **/dalton/sensor_api/get_job/<jobid>**
   | Returns the job zip file which includes the pcap(s), rule(s),
     config file, and manifest used by the job referenced by <jobid>.
     If the <jobid> is invalid or an error occurs, a HTML error page
     is returned.

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
`rulecat <https://github.com/jasonish/py-idstools>`__,
`PulledPork <https://github.com/shirkdog/pulledpork>`__, and
`Suricata-Update <https://github.com/OISF/suricata-update>`__ make it trivial to download
rulesets, combine all rules into a single ``.rules`` file, and then store it 
in the necessary location.

The Dalton Controller container includes rulecat (see the ``rulecat_script`` variable 
in ``dalton.conf``) and when the Dalton Controller first starts up, if there 
are no existing rulesets, it will attempt to download the latest Suricata and Snort rulesets 
from `rules.emergingthreats.net <https://rules.emergingthreats.net>`__.

Adding Sensors
==============

Adding sensors to Dalton is a fairly simple process.  If there isn't already 
a corresponding or compatible configuration file for the new sensor, that 
will also need to be added; see `Adding Sensor Configs <#adding-sensor-configs>`__
for more information and to use custom config files for specific sensors.

Unless a custom configuration is used, (see `Adding Sensor Configs <#adding-sensor-configs>`__),
sensors (Agents) request jobs based on
their particular engine (Suricata or Snort) and version (e.g. 5.0.0, 2.9.9.0).
Submitted jobs are queued based on the (corresponding) "Sensor Version" specified in the user
interface.  All applicable sensors pull jobs from the Controller from their respective queue, meaning
that there can be multiple Agents of the same type (engine and version) and
they will all pull from the appropriate shared queue on the Controller and
receive/run jobs on a first-come-first-served basis.

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
            - http_proxy=${http_proxy}
            - https_proxy=${https_proxy}
            - no_proxy=${no_proxy}
        image: suricata-3.2.3:latest
        container_name: suricata-3.2.3
        environment:
          - AGENT_DEBUG=${AGENT_DEBUG}
        restart: always

To add a specification for Suricata 4.0.2 (if it exists) just change the
``SURI_VERSION`` arg value from '3.2.3' to '4.0.2'.  This will cause that version
of Suricata to be downloaded and built.  The service name (e.g. 'agent-suricata-3.2.3')
container name, and image name should also be updated to be unique.  Multiple Agents with
the same engine/version can be run by keeping the ``SURI_VERSION`` and image name
the same but using different service and container names.

Example Suricata 4.0.2 specification:

.. code:: yaml

      agent-suricata-4.0.2:
        build:
          context: ./dalton-agent
          dockerfile: Dockerfiles/Dockerfile_suricata
          args:
            - SURI_VERSION=4.0.2
            - http_proxy=${http_proxy}
            - https_proxy=${https_proxy}
            - no_proxy=${no_proxy}
        image: suricata-4.0.2:latest
        container_name: suricata-4.0.2
        environment:
          - AGENT_DEBUG=${AGENT_DEBUG}
        restart: always

Rust support was added in Suricata 4.0 but is optional.  Starting with Suricata 5.0.0,
Rust is manditory.  To turn on Rust support for a Suricata 4.x Agent, set the
``ENABLE_RUST`` arg in the docker-compose file to ``--enable-rust`` for that
particular Agent specification (see below example).  Suricata 4.x Agents that have
Rust support will show up in the Web UI alongside the string, "with Rust support".

Example Suricata 4.1.4 specification with Rust support:

.. code:: yaml

      agent-suricata-4.1.4-rust:
        build:
          context: ./dalton-agent
          dockerfile: Dockerfiles/Dockerfile_suricata
          args:
            - SURI_VERSION=4.1.4
            - http_proxy=${http_proxy}
            - https_proxy=${https_proxy}
            - no_proxy=${no_proxy}
            - ENABLE_RUST=--enable-rust
        image: suricata-4.1.4-rust:latest
        container_name: suricata-4.1.4-rust
        environment:
          - AGENT_DEBUG=${AGENT_DEBUG}
        restart: always

Suricata can also have ``SURI_VERSION=current`` in which case the latest
Suricata version will be used to build the Agent.  Having a 'current' Suricata 
version specification in the ``docker-compose.yml`` file is especially convenient 
since when a new version comes out, all that has to be done is run the
``start-dalton.sh`` script and a new Dalton Agent with the latest Suricata 
version will be built and available.

Snort agents are the same way but the args to customize are ``SNORT_VERSION`` and, 
if changed, ``DAQ_VERSION``.  Example Snort specification:

.. code:: yaml

      # Snort 2.9.11 from source
      agent-snort-2.9.11:
        build:
          context: ./dalton-agent
          dockerfile: Dockerfiles/Dockerfile_snort
          args:
            - SNORT_VERSION=2.9.11
            - DAQ_VERSION=2.0.6
            - http_proxy=${http_proxy}
            - https_proxy=${https_proxy}
            - no_proxy=${no_proxy}
        image: snort-2.9.11:latest
        container_name: snort-2.9.11
        environment:
            - AGENT_DEBUG=${AGENT_DEBUG}
          restart: always

Suricata Agents should build off the Suricata Dockerfile,
``Dockerfiles/Dockerfile_suricata_rust``.

Snort Agents should build off the
Snort Dockerfile at ``Dockerfiles/Dockerfile_snort``.

Non-Docker Sensors
------------------
Sensors don't have to be Docker containers or part of the docker-compose
network to be used by the Dalton Controller; they just have to be able to 
access and talk with the Docker Controller webserver.

A Suricata or Snort machine can be turned into a Dalton Agent fairly easily. 
Requirements:

-  Engine (Suricata or Snort)
-  Python 3.6 or later
-  ``dalton-agent.py``
-  ``dalton-agent.conf``

The ``dalton-agent.conf`` file must be modified to point to the Docker 
Controller (see ``DALTON_API`` option).

For more details on the Dalton Agent configuration options, see the inline 
comments in the ``dalton-agent.conf`` file.

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
are not automatically added when Agents are built or the Controller is run; 
they must be manually added. 
However, the Dalton Controller already comes with the default (from source) config files 
for Suricata versions 0.8.1 and later, and for Snort 2.9.0 and later. 
Duplicate config files are not included.  For example, since all the Suricata 
1.4.x versions have the same (default) .yaml file, only "suricata-1.4.yaml" 
is included.

The Controller attempts to find a config file to load/use based off
the sensor engine (Suricata or Snort) and version number (e.g. 5.0.0, 2.9.9.0).

For example, if an Agent is running Suricata version 5.0.0, then the Controller will 
look for a file with the name "suricata-5.0.0.yaml" in the 
``engine-configs/suricata/`` directory.  If it can't find an 
exact match, it will attempt to find the closest match it can based off the
version number.

If a custom config is desired to be used by a particular sensor, set
the ``SENSOR_CONFIG`` variable in the Agent's ``dalton-agent.conf`` file
and place a file with the same name on the Controller in the
``engine-configs/suricata/`` directory (for Suricata) or
``engine-configs/snort/``  directory (for Snort).  If the ``SENSOR_CONFIG`` value
does not exactly match a config file on the Controller, the Controller
will look for filenames with the SENSOR_CONFIG value and extensions ".yaml", ".yml",
and ".conf".

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

Dalton includes a Web UI for
`Flowsynth <https://github.com/secureworks/flowsynth>`__ , a tool that 
facilitates network packet capture creation. The flowsynth Web UI makes it trivial
to model network traffic and test it against a Dalton Agent.

Accessing the Flowsynth WebUI can be done via the 'Flowsynth' link in the Dalton toolbar, or directly
using the '/flowsynth' URI path.
The flowsynth UI has two modes of
operation: Build and Compile. The build mode provides a wizard-like interface for
creating certain types of pcaps. The compile mode provides a direct interface to
the flowsynth compiler, allowing for the building of synth files directly in the UI.

Build Mode
----------
The Flowsynth Build mode allows for quick pcap generation using some sensible
defaults. On the 'Network Layer' vertical tab, the source and destination IP ranges can be selected.
An IP address is chosen at random from these ranges. On the 'Transport Layer' vertical tab
is the ability to choose between TCP and UDP, and optionally establish the TCP connection
with a three-way handshake. Destination and Source ports are chosen at random,
or can be set explicitly. The 'Payload' vertical tab allows the user to easily build some common
payloads. The wizards generate flowsynth syntax language, and populate the 'Compile'
tab with the content to allow for any last minute changes prior to compilation.

Binary, non-printable, and printable bytes can be represented using Hexadecimal escape sequences 
(\xhh).  Such encoding are converted to their representative bytes when the pcap is compiled. 
For example, '\x41' becomes 'A'.


Raw Payload
```````````
The raw payload wizard allows a user to rapidly model two-way communication between
a client and server.  
It is often useful for modeling custom protocols and/or binary protocols.

HTTP Payload
````````````
The HTTP  wizard makes it simple to build HTTP client requests and HTTP
server responses. The payload prompts for two types of input, an HTTP header section
and a HTTP body section.

If the 'Autocompute request Content-Length header' and/or 
'Autocompute response Content-Length header' is selected, the wizard will compute and add a
Content-Length header based on the HTTP body data.  If a Content-Length header already
exists in the HTTP Header data, it will be updated to reflect the correct size of the 
corresponding HTTP body.  If the request body is empty, a "Content-Length: 0" header 
will *not* be added; if a response body is empty, a "Content-Length: 0" header *will* be 
added.

Certificate Payload
```````````````````
The Certificate wizard makes it trivial to generate a partial SSL/TLS handshake
using a user-supplied certificate.

Compile Mode
------------
Compile mode provides a direct interface to the flowsynth compiler, allowing for 
the building of synth files directly in the UI. The compile mode UI is populated by the
build mode wizards. After the synth has been submitted, a pcap will be generated
and a download link provided. The pcap can also be directly submitted from the web interface 
to Dalton, to be used in a Suricata or Snort job.

Zeek
====

Dalton now supports Zeek as a sensor as of version 3.2.0. There is limited support in the API and
configurations/rulesets cannot be changed at runtime from the UI. However, Zeek scripts can be
added in the rulesets directory and will be executed with every run.

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
   | SSL/TLS can be configured for the Web UI.
     See `Enabling SSL/TLS on the Controller <#Enabling-SSL-TLS-on-the-Controller>`__.
   
#. | **Will this work on Windows?**
   | The native Dalton code won't work as expected on Windows without non-trivial 
     code changes. 
     However, if the Linux containers can run on Windows, then 
     it should be possible to get containers working on a Windows host.  But
     this has not been tested.
   
#. | **What is the difference between an "engine", "sensor", and "agent"?**
   | In this context those terms, for the most part, mean the same thing.
     Technically, you can think of "engine" as the IDS engine, in this
     case Suricata or Snort; "sensor" as the system running the engine; and
     "agent" as a specific system running the Dalton Agent code and checking in to
     the Dalton Controller.  "Sensor" and "Agent" are very often used
     interchangeably.

#. | **Is there Dalton Agent support for Snort version < 2.9?**
   | Currently no.  Dalton Agents that run Snort utilize the 'dump' DAQ to replay pcaps
     and DAQ wasn't introduced until Snort 2.9.  Dalton Agents for older Snort
     versions (e.g. 2.4) have been written in the past but are not part of this 
     open source release.  However, if there is a demand for such support, then
     adding support for older Snort versions will be reconsidered.

#. | **So then is Snort 3 supported?**
   | Not at this time.  Snort 3 support is certainly possible and is being
     considered.

#. | **Does Dalton support authentication such as username/password/API tokens or 
     authorization enforcement like discretionary access control?**
   | No, not in this open source release although such additions have been done
     before, including single sign on integration.  However, such enhancements 
     would require non-trivial code additions. There are some authentication 
     decorators commented out and scattered throughout the code and the Dalton 
     Agents do send an API token as part of their requests but the Dalton 
     Controller doesn't validate it.  The lack of authentication and 
     authorization does mean that it isn't difficult for malicious actors to 
     flood the Controller, submit malformed jobs, corrupt job results, dequeue
     jobs, and DoS the application.
     
#. | **How can I programmatically submit a job to Dalton?**
   | Right now, a programmatic submission must mimic a Web UI submission. In the
     future, a more streamlined and easier to use submission API may be exposed.
     Feel free to submit a pull request with this feature.

#. | **When I submit jobs to Suricata Agents with multiple pcaps, the job zipfile
     only has one pcap. What's going on?**
   | In read pcap mode, which is how the Suricata and Snort engines process pcaps,
     older version of Suricata only support the reading of a single pcap.  Therefore,
     *for jobs submitted to such older Suricata Agents*, to support
     multiple pcaps in the same Suricata job, the Dalton Controller will combine 
     the pcaps into a single file before making the job available for Agents to
     grab. By default, the pcap merging is done with
     `mergecap <https://www.wireshark.org/docs/man-pages/mergecap.html>`__.
     For more details see `Packet Captures <#Packet-Captures>`__.

#. | **Can I have more than one Agent with the same engine/version? For example, can
     I have multiple Agents running Suricata 4.0.1?**
   | Of course.  If you use the Agent containers and Docker Compose, make sure that
     the service and container name are unique between sensors.  Agents poll a
     queue on the Dalton controller for jobs based on their "TECHNOLOGY"
     (typically engine and version) and multiple Agents can poll the same queue.
     Pending jobs are given to the first Agent that requests them.

#. | **Why is it that when I try to build a Snort 2.9.0 or 2.9.0.x container, it fails when
     configuring Snort saying it can't find the 'dnet' files?**
   | Attempting to build Snort 2.9.0 and 2.9.0.x  will fail because 
     Autoconf can't find the dnet files. This was apparently fixed in 
     Snort 2.9.1 and later. If 
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
     do review the code, it is requested that you approach it with a spirit of
     charity.

#. | **I found a bug in Dalton.  What should I do?**
   | Feel free to report it and/or fix it and submit a pull request.
   
 

Authors
=======

-  David Wharton
   
-  Will Urbanski
   
Contributors
------------

-  Rob Vinson
-  George P. Burdell
-  Adam Mosesso
-  Donald Campbell
 

Feedback including bug reports, suggestions, improvements, questions,
etc. is welcome.

 
