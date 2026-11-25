"""Example on how to submit a job using the Dalton Client API.

The engine config and custom rules come from the mocks directory, the pcap from the command line.

Run it from the repository root: python -m api.examples.job_submission <pcap>
"""

import os
import sys

from api.dalton import DaltonAPI

DALTON_URL = os.getenv("DALTON_URL", "http://localhost")
SENSOR_NAME = "suricata"
CURRENT_PATH = os.getcwd()

if len(sys.argv) != 2:
    sys.exit("usage: python -m api.examples.job_submission <pcap>")
PCAP = sys.argv[1]

# create API client
dalton_client = DaltonAPI(DALTON_URL)

# this file needs to include the sensor configuration in yaml format. Make sure that the files are in the proper directory.
with open(f"{CURRENT_PATH}/api/examples/mocks/engine_conf.yaml", "r") as conf:
    configuration = conf.read()

# this file needs to include any custom rules you want to test
with open(f"{CURRENT_PATH}/api/examples/mocks/custom_rules.rules", "r") as cust:
    custom_rules = cust.read()

# get rulesets and sensor techs to use in job submission parameters
dalton_rulesets = dalton_client.get_prod_rulesets(SENSOR_NAME)
dalton_sensor_techs = dalton_client.get_sensor_tech(SENSOR_NAME)

# since techs and rulesets are a list we use a loop to get the corresponding tech and ruleset
# you will probably use this if you want to test with multiple versions of the sensor
with open(PCAP, "rb") as pcap:
    pcap_bytes = pcap.read()
for tech in dalton_sensor_techs:
    # bytes can be sent any number of times; an open file would be read to its end by the first job
    files = {"coverage-pcap0": (os.path.basename(PCAP), pcap_bytes)}
    jid = dalton_client.submit_job(
        sensor_tech=tech,
        prod_ruleset=dalton_rulesets[0],
        configuration=configuration,
        custom_rules=custom_rules,
        files=files,
    )
    print(f"{tech}: {jid}")
