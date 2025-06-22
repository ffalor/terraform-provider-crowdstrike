#!/bin/bash

# Device control policies can be imported using their policy ID
# You can find the policy ID in the CrowdStrike Falcon console or by using the device control policy data source

terraform import crowdstrike_device_control_policy.example "policy-id-here"