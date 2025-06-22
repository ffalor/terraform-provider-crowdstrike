#!/bin/bash

# Import an existing CrowdStrike firewall rule group
# Replace "rule-group-id" with the actual rule group ID from your CrowdStrike environment

terraform import crowdstrike_firewall_rule_group.example rule-group-id