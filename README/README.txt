          Language:       Python

          Version:        3.24

          Original Date:  05-02-2015

          Author:         Derek Arnold

          Company:        Obelisk Security (formerly Accuvant)

          Purpose:        Gathers various IPs from open source threat lists and parses them into a Splunk-friendly key/value pair format.

          Syntax:         python ./optiv_threat_lists.py

          Copyright (C):  2015 Derek Arnold (ransomvik)

          License:        This program is free software: you can redistribute it and/or modify
                          it under the terms of the GNU General Public License as published by
                          the Free Software Foundation, either version 3 of the License, or
                          any later version.

                          This program is distributed in the hope that it will be useful,
                          but WITHOUT ANY WARRANTY; without even the implied warranty of
                          MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
                          GNU General Public License for more details. See <http://www.gnu.org/licenses/>

          Change Log:     05-01-2015 DPA        Created.
                          08-08-2015 DPA        Added TOR, OpenBL, split out Palevo into its own function.
		          10-07-2015 DPA        Many new features and functionality.
                          02-12-2016 DPA	Added email alerting feature, improved search speed.
                          05-16-2016 DPA        Incorporated lookup tables to improve search speed further.
                          08-27-2016 DPA        Split the app into obelisk-threat-intel and TA_obelisk-threat
                          05-06-2017 DPA        Disabled OpenBL, Binary Defense. Added NoThink, Darklist.de, and Blocklist.de


Overview:
Obelisk Threat Intel is a Splunk App that automatically correlates your data
with several popular open threat lists. After a few mouse clicks we can start
hunting for log sources that are reaching out to, or being attacked from,
known attackers. The app can provide increased visibility to potentially
malicious activity going on in the organization.

Features:
*Threat list visualization that shows where most of the attackers are located on a globe.
*Easily choose indexes, sourcetypes, or hosts for log entries that match
threat list destination IPs, domains, and URLs
*Email alerting feature.
*Easy setup screen.
*IP search feature that displays threat list activity.
*Domain search feature that displays threat list activity.
*RSS feed which will poll several information security news sites and consolidate the stories on one page.
*Updated information is pulled down from the web every 8 hours.

Prerequisites:
*Splunk 6.3.x or above
*Linux or Windows Operating System
*If there is a distributed environment, install the app on the ad hoc search head only.
*Web access is required to several threat lists and news RSS sites.
*For the Globe visualization, install the Custom Visualizations app found at:
	https://splunkbase.splunk.com/app/2717/

Support:
This is an open source project, no support provided, public repository available.
                        https://github.com/ransomvik/TA_obelisk-threat

Special note:
As of version 3.10, the app has split into two: obelisk-threat-intel (this app) and TA_obelisk-threat.
The obelisk-threat-intel app continues to be installed on search heads. the TA_obelisk-threat app
is to be installed on a single heavy forwarder in the environment only.

Install matrix:
+-----------------+--------------------+
| Splunk role     | App to install     |
+=================+====================+
| Indexer         | none*              |
+-----------------+--------------------+
| Search head     | obelisk-threat-intel |
+-----------------+--------------------+
| Heavy forwarder | TA_obelisk-threat    |
+-----------------+--------------------+
*create an "optiv" index on each indexer

Install:
*Login to Splunk as an admin.
*Go to Apps->Manage apps
*Click Install app from file.
*Browse to the file folder with the app .tar.gz file.
*Choose the file and click OK.
*After the app is uploaded and installed, restart Splunk.
*Launch the app to complete the setup screen.

Upgrade Instructions:
*Stop Splunk
*Remove the app from the directory structure on Linux:
rm –rf /opt/splunk/etc/apps/obelisk-threat-intel
rm -rf /opt/splunk/etc/apps/TA_obelisk-threat
or on Windows:
c:\Program Files\Splunk\etc\apps\obelisk-threat-intel
c:\Program Files\Splunk\etc\apps\TA_obelisk-threat
*Start Splunk
*Install using the steps shown in the Install section.
*After the app is uploaded and installed, restart Splunk.

External data sources *URLs*:
The app may contact the following URLs to pull its information:
http://www.us-cert.gov/ncas/current-activity.xml
http://feeds.feedburner.com/nakedsecurity?format=xml
http://www.symantec.com/connect/item-feeds/blog/3241/feed/all/en/all
http://feeds.feedburner.com/securityweek
http://threatpost.com/feed
http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt
http://rules.emergingthreats.net/blockrules/compromised-ips.txt
http://www.binarydefense.com/banlist.txt
https://sslbl.abuse.ch/blacklist/sslipblacklist.csv
https://reputation.alienvault.com/reputation.generic
https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist
https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist
http://malc0de.com/bl/IP_Blacklist.txt
https://check.torproject.org/exit-addresses
http://www.openbl.org/lists/base_1days.txt
http://avant.it-mate.co.uk/dl/Tools/hpHosts/hosts.txt
http://hosts-file.net/hphosts-partial.txt
https://isc.sans.edu/feeds/suspiciousdomains_High.txt
http://www.malwaredomainlist.com/hostslist/hosts.txt
https://openphish.com/feed.txt
http://data.phishtank.com/data/online-valid.csv
