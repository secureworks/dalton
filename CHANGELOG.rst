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
