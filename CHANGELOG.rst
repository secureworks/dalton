****************
Dalton Changelog
****************

2.0.0 (2017-11-15)
##################

Initial public release.

Special thanks: SuriCon 2017

2.x.x
#####

Tweaks, fixes, and updates over the years; not well-documented here.

3.0.0 (2021-03-10)
##################

* Move to Python 3 from Python 2.
* Better Suricata EVE log support in UI now that unified2 is no longer supported with Suricata v6; can format/highlight, view in "dark mode", and download directly from the UI.
* Support for running jobs using Suricata socket control and enabled it by default.  Now Suricata doesn't have to restart (load config, rules, etc.) between jobs if the config and rules stay the same.
* Ability to easily enable SSL/TLS on the Controller.
* Additions, updates, and fixes to the API to reduce complexity and make it work as expected. 
* Can now submit multiple pcaps (or an archive with multiple pcaps) and have them processed as individual jobs.
* Display the number of alerts for finished jobs on the Queue page.
* Ubuntu docker containers now use 18.04.
* Use more recent versions of libraries, e.g. flask, jquery, etc.
* Minor UI reorganization.  Variables are no longer bifurcated from the rest of the config.
* Dalton agent now has configurable "config" parameter that it can submit to tell controller which config to use.
* Address issues # 113, 123, 128, 132 (https://github.com/secureworks/dalton/issues/).
* Updated documentation to reflect current reality.
* Sundry other bug fixes and enhancements.

3.1.0 (2021-06-18)
##################

Contributors: Donald Campbell, Adam Mosesso

* Added ability to select multiple pcaps from the file upload dialog.
* Support for dumping (displaying) inspection buffers from alerts.
* Minor cleanup.

3.1.1 (2021-09-29)
##################

* Fixed UI issue where the "Dump buffers" option was being shown for incompatible engine versions. (issue #139)
* Server side enforcement ensuring "Dump buffers" will only be attempted for compatible versions.
* Bumped the default agent versions in the ``docker-compose.yml`` file to be the latest.
* Added ``INSTALL-AWS.rst`` file with instructions for quickly and easily spinning up Dalton in AWS.

3.2.0 (2022-02-28)
##################

* Added support for Zeek as a sensor

3.2.1 (2022-03-10)
##################

* Added explicit requirement for ``itsdangerous==2.0.1``

3.2.2 (2022-04-28)
##################

*  Specify Jinja2 version in requirements

3.2.3 (2022-05-26)
##################

* Added share_expire to dalton.conf
* Recreate job submission page based on JID
* Added ability to pull PCAPs from job file
* Add share link to UI and using ruleset from job
* Added job zip modification time adjustment
* Added PCAP drag and drop to jobs
* Add font size for PCAP drop
* Adjusted drag and drop text size in dalton.css
* Edit PCAP drop CSS

3.2.4 (2022-08-16)
##################

* Update URI for Suricata source code download.

3.2.5 (2022-09-27)
##################

* Speed up Zeek build on systems with multiple processing units by using simultaneous jobs when running 'make'. (#155)
* Fix Zeek won't run if no scripts in path (#156)

3.3.0 (2023-05-12)
##################

* Adds script to submit jobs (#158)
* adds API client and example, addresses review comments
* updates README
* updates comments

Co-authored-by: Xenia Mountrouidou (drx) <pmountrouidou@cyberadapt.com>

3.3.1 (2023-05-12)
##################

* Spelling

Signed-off-by: Josh Soref <2119212+jsoref@users.noreply.github.com>

3.3.2 (2023-06-06)
##################

* Update error catching for suri7

Author: zoomequipd <4827852+zoomequipd@users.noreply.github.com>

3.3.3 (2024-07-11)
##################

* Fixes issue where unable to build suricata container

Author: Spencer Owen <owenspencer@gmail.com>

3.3.4 (2024-08-14)
##################

Bring sensor configs up to date with current versions

* Download ET Suricata 5.0 ruleset since the 4.0 ruleset won't work on latest supported Suricata versions.
* set default enabled sensors to be up to date versions
* add Suricata 7 YAML config file
* add conf file for snort-2.9.20 even though it is functionally unchanged from snort-2.9.11
* move suricata-7.0.0.yaml to proper location

Author: whartond <github@davidwharton.net>

3.3.5 (2024-09-10)
##################

* Be able to pre-fill the flowsynth compile page via GET or POST
* also ran isort

Author: Robin Koumis (SecureWorks) <rkoumis@secureworks.com>

3.3.6 (2024-09-23)
##################

Zeek Enhancements (#177)
* Dalton UI now will have an option to provide custom zeek script in zeek sensor job creation page. You can either upload custom script file or write the script (or both) in the Dalton UI, and can run pcaps using those custom scripts.
* Add zeek version 7 and version 6 ; remove zeek version 4.

Author: Nikhileswar Reddy <nreddy@octolabs.io>

4.0.0
##################

* Use pyproject.toml (#184) (#189)
* Use ruff format to format the code (#183) (#190)
* Use ruff check --fix to make style changes (#183) (#191)
