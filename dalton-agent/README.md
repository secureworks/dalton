## Dalton Agent

Python script that runs on Snort or Suricata systems.

This script polls the Dalton Controller and if there are
jobs to run, downloads, runs, and reports the results
of the job.

For Agent configuration, see inline comments in `dalton-agent.conf`.

```
Usage: dalton-agent.py [options]

Options:
  -h, --help            show this help message and exit
  -c CONFIGFILE, --config=CONFIGFILE
                        path to config file [default: dalton-agent.conf]
```
