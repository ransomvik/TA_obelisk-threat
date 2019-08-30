#!/bin/bash

#starter_script.sh

THIS_APP_NAME="TA_obelisk-threat"
MAX_DAYS_TO_KEEP=2

echo "[*] Keep log files for: $MAX_DAYS_TO_KEEP days."

echo "[*] Executing threat list script."
/opt/splunk/bin/splunk cmd python /opt/splunk/etc/apps/TA_obelisk-threat/bin/obelisk_threat_intel.py

echo "Python scripts are done, looking for log files to clear."
find /opt/splunk/etc/apps/TA_obelisk-threat/logs/obelisk*.log -type f -mtime +$MAX_DAYS_TO_KEEP -delete
