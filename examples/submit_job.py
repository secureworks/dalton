"""Example of how to submit a Dalton job using Python HTTP requests."""
import requests
import os

DALTON_URL = os.getenv("DALTON_URL", "localhost")

# this file needs to include the sensor configuration in yaml format. Make sure that the files are in the proper directory.
conf = open("engine_conf.yaml", "r") 
configuration = conf.read()

# this file needs to include any custom rules you want to test
cust = open("custom_rules.rules", "r") 
custom_rules = cust.read()

# in this example we use suricata as sensor
data = {
  "sensor_tech": "suricata/6.0.4/suricata.yaml",
  "optionProdRuleset": "prod",
  "prod_ruleset": "/opt/dalton/rulesets/suricata/suricata.rules",
  "custom_engineconf": configuration,
  "custom_ruleset": custom_rules,
  "teapotJob": 1
}

# test_job.pcap can be substituted with any target pcap name. 
pcap = open('test_job.pcap', 'rb') 
files = {"coverage-pcap0": ("test_job.pcap", pcap)}

response = requests.post(f"{DALTON_URL}/dalton/coverage/summary", data=data, files=files)
