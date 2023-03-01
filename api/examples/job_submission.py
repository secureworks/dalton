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

# not sure if I should use this
# response = requests.get(f"{DALTON_URL}/dalton/controller_api/get-current-sensors-json-full")
# sample response text: '{"e1661859b3cb4449bf7be8000d9d016f": {"uid": "8a204e8152b4", "ip": "172.19.0.2", "time": "Feb 28 21:39:38 (0 minutes ago)", "tech": "suricata/6.0.8/suricata-cyberadapt.yaml", "agent_version": "3.1.1"}}'

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
