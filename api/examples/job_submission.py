"""Example on how to submit a job using the Dalton Client API. Mock data is in mocks directory."""

import os

from api.dalton import DaltonAPI

DALTON_URL = os.getenv("DALTON_URL", "http://localhost")
SENSOR_NAME = "suricata"
CURRENT_PATH = os.getcwd()

# create API client
dalton_client = DaltonAPI(DALTON_URL)

# this file needs to include the sensor configuration in yaml format. Make sure that the files are in the proper directory.
conf = open(f"{CURRENT_PATH}/api/examples/mocks/engine_conf.yaml", "r")
configuration = conf.read()

# this file needs to include any custom rules you want to test
cust = open(f"{CURRENT_PATH}/api/examples/mocks/custom_rules.rules", "r")
custom_rules = cust.read()

# get rulesets and sensor techs to use in job submission parameters
dalton_rulesets = dalton_client.get_prod_rulesets(SENSOR_NAME)
dalton_sensor_techs = dalton_client.get_sensor_tech(SENSOR_NAME)

# since techs and rulesets are a list we use a loop to get the corresponding tech and ruleset
# you will probably use this if you want to test with multiple versions of the sensor
for tech in dalton_sensor_techs:
    # have to reread the file to send it to multiple instances of the sensor
    pcap = open(f"{CURRENT_PATH}/api/examples/mocks/test_job.pcap", "rb")
    files = {"coverage-pcap0": ("test_job.pcap", pcap)}
    dalton_client.submit_job(
        sensor_tech=tech,
        prod_ruleset=dalton_rulesets[0],
        configuration=configuration,
        custom_rules=custom_rules,
        files=files,
    )
