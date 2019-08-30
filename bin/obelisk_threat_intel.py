#!/usr/bin/python

##########################################################################################################################
##
##          Script:         obelisk_threat_intel.py
##
##          Language:       Python
##
##          Version:        3.42
##
##          Original Date:  05-02-2015
##
##          Author:         Derek Arnold
##
##          Company:        Obelisk Security
##
##          Purpose:        Gathers various IPs from open source threat lists and parses them into a Splunk-friendly key/value pair format.
##
##          Syntax:         python ./obelisk_threat_intel.py
##
##          Copyright (C):  2018 Derek Arnold (ransomvik)
##
##          License:        This program is free software: you can redistribute it and/or modify
##                          it under the terms of the GNU General Public License as published by
##                          the Free Software Foundation, either version 3 of the License, or
##                          any later version.
##
##                          This program is distributed in the hope that it will be useful,
##                          but WITHOUT ANY WARRANTY; without even the implied warranty of
##                          MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
##                          GNU General Public License for more details. See <http://www.gnu.org/licenses/>
##
##          Change Log:     05-01-2015 DPA      Created.
##                          08-08-2015 DPA      Added TOR, OpenBL, split out Palevo into its own function.
##                          09-06-2015 DPA      Cross-platform enhancements.
##                          09-17-2015 DPA      Added domains and URLs to the mix.
##                          03-19-2016 DPA      Added threat lists from AutoShun and CI Badguys
##                          12-04-2016 DPA      More robust handling of AlienVault.
##                          02-03-2017 DPA      3 new Ransomware lists. Disabled AutoShun.
##                          04-20-2017 DPA      Disabled Palevo and Binary Defense. Added conf file for urls.
##                          05-02-2017 DPA      Enabled NoThink SSH Blacklist, Blocklist.de, and Darklist.de
##                          03-25-2018 DPA      Re-branded to TA_obelisk-threat
##			    06-13-2018 DPA	New Threat Lists
##
##########################################################################################################################


from time import gmtime, strftime

import urllib2
import re

#Original script concept from a bash script that was a posting on: www.deepimpact.io/blog/splunkandfreeopen-sourcethreatintelligencefeeds


import os
import subprocess
import socket

this_app_name = "TA_obelisk-threat"

script_version = "3.4.6"
#user_agent_string = "Obelisk Threat Intel v" + script_version
user_agent_string = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:67.0) Gecko/20100101 Firefox/67.0"
#user_agent_string = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.6 Safari/537.36" 

urlList = []

urlfile_name_txt = "threatlist_urls.conf"
urlfile_name =  os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'config', urlfile_name_txt)

logfile_name_log =  "obelisk_threat_lists_script" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
#logfile_name_txt = "obelisk_threat_lists_misc" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
phishtank_logfile_name_log =  "obelisk_phishtank" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
hphosts_logfile_name_log =  "obelisk_hphosts" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
alienvault_logfile_name_log =  "obelisk_alienvault" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
logfile_name_txt = "obelisk_threat_lists_misc" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
bambenek_logfile_name_log =  "obelisk_bambenek" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
talos_logfile_name_log = "obelisk_talos_intel" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
ransomware_tracker_abuse_ch_log = "obelisk_ransomware_tracker" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
nothinkssh_log = "obelisk_nothink_ssh" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
blocklistde_log = "obelisk_blocklist_de" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
darklistde_log = "obelisk_darklist_de" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
joewein_log = "obelisk_joewein" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log" 
greensnow_log = "obelisk_greensnow" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
spys_proxy_log = "obelisk_spysproxy" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
badips_log = "obelisk_badips" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
socks_proxy_log = "obelisk_socksproxy" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"
team_cymru_bogons_log = "obelisk_teamcyrubogons" + strftime("%m-%d-%Y-%H-%M-%S", gmtime()) + ".log"

logfile_name =  os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', logfile_name_log)
phishtank_logfile_name =  os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', phishtank_logfile_name_log)
bambenek_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', bambenek_logfile_name_log)
hphosts_logfile_name =  os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', hphosts_logfile_name_log)
alienvault_logfile_name =  os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', alienvault_logfile_name_log)
talos_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', talos_logfile_name_log)
ransomware_tracker_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name,'logs', ransomware_tracker_abuse_ch_log)
nothink_ssh_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', nothinkssh_log)
blocklistde_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', blocklistde_log)
darklistde_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', darklistde_log)
joewein_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', joewein_log)
greensnow_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', greensnow_log)
spys_proxy_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', spys_proxy_log)
badips_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', badips_log)
socks_proxy_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', socks_proxy_log)
team_cymru_bogons_logfile_name = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', team_cymru_bogons_log)
outputfile_name =  os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', this_app_name, 'logs', logfile_name_txt)


url_file = open(urlfile_name,'r')

print "logfile_name: " + logfile_name

lf = open(logfile_name,'w')
of = open(outputfile_name,'w')
phishtank_lf = open(phishtank_logfile_name,'w')
bambenek_lf = open(bambenek_logfile_name,'w')
hphosts_lf = open(hphosts_logfile_name,'w')
alienvault_lf = open(alienvault_logfile_name,'w')
talos_lf = open(talos_logfile_name,'w')
ransomware_lf = open(ransomware_tracker_logfile_name,'w')
nothinkssh_lf = open(nothink_ssh_logfile_name,'w')
blocklistde_lf = open(blocklistde_logfile_name,'w')
darklistde_lf = open(darklistde_logfile_name,'w')
joewein_lf = open(joewein_logfile_name,'w')
greensnow_lf = open(greensnow_logfile_name,'w')
spys_proxy_lf = open(spys_proxy_logfile_name, 'w')
badips_lf = open(badips_logfile_name, 'w')
socks_proxy_lf = open(socks_proxy_logfile_name, 'w')
cymru_bogons_lf = open(team_cymru_bogons_logfile_name, 'w')

#Threat List URL's go here. Note that each list requires special parsing rules contained below.
for url in url_file.readlines():
    url = url.strip('\n')

    url_formatted = url.split(',')

    url = url_formatted[0]

    is_url = re.match( r'^(http|https)\:', url, re.I)
    if is_url:
        #print "[*] Reading from URL: " + url
        urlList.append(url)

def getUrl(url,use_user_agent_bool):

    #url = urlList[0].strip('\n')
    print "URL: " + url
    print "user_agent_bool: " + use_user_agent_bool
    urlResults=""
    #usock=""
    if (use_user_agent_bool == 'true'):
        #req = urllib2.Request(url, "",headers={'User-Agent' : user_agent_string})
        req = urllib2.Request(url, headers={'User-Agent' : "Magic Browser"}) 
    else:
        req = urllib2.Request(url)

    #req = urllib2.Request(url, headers={'User-Agent' : "Magic Browser"}) 


    #Testing the URL here, print out error messages found.
    try: urllib2.urlopen(req, timeout=15)
    except urllib2.URLError, e:
        print e.reason
        lf.write( str(e.reason) + "\n")
    try:
        usock = urllib2.urlopen(req, timeout=15)
    except socket.timeout, e:
        #import socket
        print('HTTPError timeout ')
        lf.write('HTTPError timeout ')
        return -1
    except urllib2.HTTPError, e:
        print('HTTPError = ' + str(e.code))
        lf.write('HTTPError = ' + str(e.code))
        return -1
    except urllib2.URLError, e:
        print('URLError = ' + str(e.reason))
        lf.write('URLError = ' + str(e.reason))
        return -1
    except httplib.HTTPException, e:
        print('HTTPException')
        lf.write('HTTPException')
        return -1
    except Exception:
        import traceback
        print ("Some other error happened:", traceback.format_exc())
        lf.write("Some other error happened", traceback.format_exc())
        return -1

    #usock = urllib2.urlopen(req)

    #************************************
    urlResults=usock.read()
    return urlResults

def parseTalosIntel(urlResults):
    talosIP = ['']

    talosIP_formatted = ['']

    talosIP = urlResults.split("\n")

    for line in talosIP:
        if (len(line) > 5):
            talosIP_formatted.append("dest_ip=" + line + " threat_list_name=talos_intel_IPs")

    print "Finished retrieving " + str(len(talosIP_formatted)) + " Talos Intel IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    talos_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    talos_lf.write( "\n".join(talosIP_formatted))
    lf.write('\nRetrieved ' + str(len(talosIP_formatted)) + ' Talos Intel IPs.')

def parseRansomwareAbuseCHIPlist(urlResults):
    ransomwareAbuseIPNoHeaders = ['']
    ransomwareAbuseIP = ['']
    ransomwareAbuseIP_formatted = ['']

    ransomwareAbuseIPResults = urlResults.split("#########################################################")

    ransomwareAbuseIPNoHeaders = ransomwareAbuseIPResults[2:]

    for line in ransomwareAbuseIPNoHeaders:
        parseRansomwareLine = line.split('\n')

    for line in parseRansomwareLine:
        if (len(line) > 3 and not line.lstrip().startswith('#')):
            ransomwareAbuseIP_formatted.append("dest_ip=" + str(line) + " threat_list_name=ransomware_Abuse_CH_IPs" )

    print "Finished retrieving " + str(len(ransomwareAbuseIP_formatted)) + " Ransomware Abuse CH IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write( "\n".join(ransomwareAbuseIP_formatted))
    lf.write('\nRetrieved ' + str(len(ransomwareAbuseIP_formatted)) + ' Ransomware Abuse CH IPs.')

def parseSocksProxyIPlist(urlResults):
    socksproxyIPNoHeaders = ['']
    socksproxyIP = ['']
    socksproxyIP_formatted = ['']
    parsesocksproxyLine = ['']

    socksproxyIPResults = urlResults.split("\n")

    #socksproxyIPNoHeaders = socksproxyIPResults[20:]

    #for line in socksproxyIPNoHeaders:
    #    parsesocksproxyLine = line.split('\n')

    for line in socksproxyIPResults:
        if (len(line) > 3 and not line.lstrip().startswith('#')):
            socksproxyIP_formatted.append("dest_ip=" + str(line) + " threat_list_name=socks_proxy_IPs" )

    print "Finished retrieving " + str(len(socksproxyIP_formatted)) + " Socks Proxy IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    socks_proxy_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    socks_proxy_lf.write( "\n".join(socksproxyIP_formatted))
    lf.write('\nRetrieved ' + str(len(socksproxyIP_formatted)) + ' Socks Proxy IPs.')

def parseTeamCymruBogonCIDRlist(urlResults):
    teamCymruCIDR = ['']
    teamCymruCIDR_formatted = ['']

    teamCymruCIDR = urlResults.split("\n")
    
    for line in teamCymruCIDR:
        if (len(line) > 3 and not line.lstrip().startswith('#')):
            teamCymruCIDR_formatted.append("dest_cidr=" + str(line) + " threat_list_name=team_cymru_cidrs" )

    print "Finished retrieving " + str(len(teamCymruCIDR_formatted)) + " Team Cymru CIDRs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    cymru_bogons_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    cymru_bogons_lf.write( "\n".join(teamCymruCIDR_formatted))
    lf.write('\nRetrieved ' + str(len(teamCymruCIDR_formatted)) + ' Team Cymru CIDRs.')

def parseRansomwareAbuseCHDomainlist(urlResults):
    ransomwareAbuseDomainNoHeaders = ['']
    ransomwareAbuseDomain = ['']
    ransomwareAbuseDomain_formatted = ['']

    ransomwareAbuseDomainResults = urlResults.split("#########################################################")

    ransomwareAbuseDomainNoHeaders = ransomwareAbuseDomainResults[2:]

    for line in ransomwareAbuseDomainNoHeaders:
        parseRansomwareLine = line.split('\n')

        for line in parseRansomwareLine:
            if (len(line) > 3 and not line.lstrip().startswith('#')):
                ransomwareAbuseDomain_formatted.append("dest=" + str(line) + " threat_list_name=ransomware_Abuse_CH_domains" )

    print "Finished retrieving " + str(len(ransomwareAbuseDomain_formatted)) + " Ransomware Abuse CH Domains."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write( "\n".join(ransomwareAbuseDomain_formatted))
    lf.write('\nRetrieved ' + str(len(ransomwareAbuseDomain_formatted)) + ' Ransomware Abuse CH Domains.')

def parseNoThinkSSHBlacklist(urlResults):
    nothinkSSHIPIP = ['']
    nothinkSSHIPIP_formatted = ['']

    nothinkSSHIPIP = urlResults.split('\n')

    for dest_ip in nothinkSSHIPIP[3:]:
        if (len(dest_ip) > 3):
            is_ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dest_ip)
            if is_ip:
                nothinkSSHIPIP_formatted.append("dest_ip=" + str(dest_ip) + " threat_list_name=no_think_ssh_blacklist_ips" )

    print "Finished retrieving " + str(len(nothinkSSHIPIP_formatted)) + " No Think SSH Blacklist IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    nothinkssh_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    nothinkssh_lf.write( "\n".join(nothinkSSHIPIP_formatted))
    lf.write('\nRetrieved ' + str(len(nothinkSSHIPIP_formatted)) + ' No Think SSH Blacklist IPs.')

def parseBlocklistde(urlResults):
    blocklistdeIP = ['']
    blocklistdeIP_formatted = ['']

    blocklistdeIP = urlResults.split('\n')

    for dest_ip in blocklistdeIP:
        if (len(dest_ip) > 3):
            is_ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dest_ip)
            if is_ip:
                blocklistdeIP_formatted.append("dest_ip=" + str(dest_ip) + " threat_list_name=blocklist_de_ips" )

    print "Finished retrieving " + str(len(blocklistdeIP_formatted)) + " Blocklist.de IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    blocklistde_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    blocklistde_lf.write( "\n".join(blocklistdeIP_formatted))
    lf.write('\nRetrieved ' + str(len(blocklistdeIP_formatted)) + ' Blocklist.de IPs.')

def parseDarklistde(urlResults):
    darklistdeIP = ['']
    darklistdeIP_formatted = ['']

    darklistdeIP = urlResults.split('\n')

    for dest_ip in darklistdeIP:
        if (len(dest_ip) > 3):
            is_ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dest_ip)
            if is_ip:
                is_cidr = re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2})',dest_ip)
                if not is_cidr:
                    darklistdeIP_formatted.append("dest_ip=" + str(dest_ip) + " threat_list_name=darklist_de_ips" )

    print "Finished retrieving " + str(len(darklistdeIP_formatted)) + " Darklist.de IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    darklistde_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    darklistde_lf.write( "\n".join(darklistdeIP_formatted))
    lf.write('\nRetrieved ' + str(len(darklistdeIP_formatted)) + ' Darklist.de IPs.')

def parseGreenSnow(urlResults):
    greensnowIP = ['']
    greensnowIP_formatted = ['']

    greensnowIP = urlResults.split('\n')

    for dest_ip in greensnowIP:
        if (len(dest_ip) > 3):
            is_ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', dest_ip)
            if is_ip:
                greensnowIP_formatted.append("dest_ip=" + str(dest_ip) + " threat_list_name=green_snow_blacklist" )

    print "Finished retrieving " + str(len(greensnowIP_formatted)) + " Green Snow Blacklist IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    greensnow_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    greensnow_lf.write( "\n".join(greensnowIP_formatted))
    lf.write('\nRetrieved ' + str(len(greensnowIP_formatted)) + ' Green Snow Blacklist IPs.')

def parseJoeWein(urlResults):
    joeweinIP = ['']
    joeweinIP_formatted = ['']

    joeweinIP = urlResults.split('\n')

    for dest in joeweinIP:
        if (len(dest) > 8):
            is_domain = re.search(r'^([a-zA-Z-0-9]+\.\w+)$', dest)
            if is_domain:
                joeweinIP_formatted.append("dest=" + str(dest) + " threat_list_name=joe_wein_domains" )

    print "Finished retrieving " + str(len(joeweinIP_formatted)) + " Joe Wein Blacklist Domains."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    joewein_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    joewein_lf.write( "\n".join(joeweinIP_formatted))
    lf.write('\nRetrieved ' + str(len(joeweinIP_formatted)) + ' Joe Wein Blacklist Domains.')

def parseSpysProxy(urlResults):
    spysproxyIP = ['']
    spysproxyIP_formatted = ['']
    tempIP = ""
    tempPort = ""
    tempCountry = "unknown"
    tempAnonymity = ""
    tempSSL = ""
    tempGoogle = ""

    spysproxyIP = urlResults.split('\n')

    for line in spysproxyIP:
        if (len(line) > 3):
            is_ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if is_ip:
                tempIP = str(is_ip.group())
                is_port = re.search(r':(\d{1,5})\s', line)
                if is_port:
                    tempPort = str(is_port.group(1))
                is_country = re.search(r'\d{1,5}\s(\w{1,2})\-', line)
                if is_country:
                    tempCountry = str(is_country.group(1))
                spysproxyIP_formatted.append("dest_ip=" + str(tempIP) + " dest_port=" + str(tempPort)  + " Country=" + str(tempCountry) + " threat_list_name=spys_proxy" )

    print "Finished retrieving " + str(len(spysproxyIP_formatted)) + " Spys Proxy IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    spys_proxy_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    spys_proxy_lf.write( "\n".join(spysproxyIP_formatted))
    lf.write('\nRetrieved ' + str(len(spysproxyIP_formatted)) + ' Spys Proxy IPs.')

def parseBadIPsList(urlResults):
    badIP = ['']
    badIP_formatted = ['']
    badIP = urlResults.split('\n')

    for line in badIP:
        if (len(line) > 3):
            is_ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', line)
            if is_ip:
                tempIP = str(is_ip.group())
                badIP_formatted.append("dest_ip=" + str(tempIP) + " threat_list_name=badips_com_ips")

    print "Finished retrieving " + str(len(badIP_formatted)) + " Badips.com IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    badips_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    badips_lf.write( "\n".join(badIP_formatted))
    lf.write('\nRetrieved ' + str(len(badIP_formatted)) + ' Badips.com IPs.')


def parseRansomwareAbuseCHURLlist(urlResults):
    ransomwareAbuseURLNoHeaders = ['']
    ransomwareAbuseURL = ['']
    ransomwareAbuseURL_formatted = ['']

    ransomwareAbuseURLResults = urlResults.split("#########################################################")

    ransomwareAbuseURLNoHeaders = ransomwareAbuseURLResults[2:]

    for line in ransomwareAbuseURLNoHeaders:
        parseRansomwareLine = line.split('\n')

        for line in parseRansomwareLine:
            if (len(line) > 3):
               ransomwareAbuseURL_formatted.append("url=" + str(line) + " threat_list_name=ransomware_Abuse_CH_URLs" )

    print "Finished retrieving " + str(len(ransomwareAbuseURL_formatted)) + " Ransomware Abuse CH URLs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    ransomware_lf.write( "\n".join(ransomwareAbuseURL_formatted))
    lf.write('\nRetrieved ' + str(len(ransomwareAbuseURL_formatted)) + ' Ransomware Abuse CH URLs.')



def parseBambenekconsultingIPList(urlResults):
    ##############################################################
    bambenekIP = ['']
    bambenekIP_formatted = ['']

    bambenekRowSplit = ['']

    bambenekResults = ['']

    bambenekNoHeaders = ['']

    bambenekResults = urlResults.split("#############################################################")

    bambenekNoHeaders = bambenekResults[2:]
    #print bambenekNoHeaders

    for line in bambenekNoHeaders:
        parseBambenekLine = line.split('\n')
        for cell in parseBambenekLine:
            parseBambenekCell = cell.split(',')
            if (len(parseBambenekCell) > 2):
                bambenekIP_formatted.append("dest_ip=" + parseBambenekCell[0] + " threat_list_name=bambenekIPs threat_description=\"" + parseBambenekCell[1] + "\" url=" + parseBambenekCell[3])
    print "Finished retrieving " + str(len(bambenekIP_formatted)) + " Bambenek IPs."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    bambenek_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    bambenek_lf.write( "\n".join(bambenekIP_formatted))
    lf.write('\nRetrieved ' + str(len(bambenekIP_formatted)) + ' Bambenek IPs.')

def parsePhishTankURLList(urlResults):
    phishTankURL = ['']
    phishTankURL_formatted = ['']
    phishTankRowSplit = ['']

    phishTankURL = urlResults.split('\n')

    for csvrow in phishTankURL[1:-1]:
        phishTankRowSplit = ['']
        phishTankRowSplit = csvrow.split(',')
        if (len(phishTankRowSplit) > 7):
            if (phishTankRowSplit[4] != 'yes'):
                phishTankRowSplit[4] = 'unknown'
            if (phishTankRowSplit[6] != 'yes'):
                phishTankRowSplit[6] = 'unknown'
            if (len(phishTankRowSplit[2]) < 12):
                phishTankRowSplit[2] = 'unknown'
            phishTankURL_formatted.append('url=' + phishTankRowSplit[1].lstrip('"') + ' threat_list_name=Phish_Tank_URLs verified=' + phishTankRowSplit[4] + ' spoofed_org=' + phishTankRowSplit[7] + ' phishing_site_online=' + phishTankRowSplit[6] + ' phish_tank_info_url=' + phishTankRowSplit[2])

    print "Finished retrieving " +str(len(phishTankURL_formatted))+ " Phish Tank URLs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    phishtank_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    phishtank_lf.write( "\n".join(phishTankURL_formatted))
    lf.write('\nRetrieved ' + str(len(phishTankURL_formatted)) + ' Phish Tank URLs.')

def parseOpenPhishURLList(urlResults):
    openPhishURL = ['']
    openPhishURL_formatted = ['']

    openPhishURL = urlResults.split('\n')


    for url in openPhishURL[:-1]:
        openPhishURL_formatted.append('url=' + url.strip() + ' threat_list_name=Open_Phish_URLs')
    #m = re.findall('^#Site^(.*?)^',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(.*\..*|.*\..*\..*|.*\..*\..*\..*|.*\..*\..*\..*\..*?)',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+)$',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('^(((.*\..*)|(.*\..*\..*)|(.*\..*\..*\..*)))$',urlResults,re.DOTALL|re.MULTILINE)
    #m = re.findall('(.*\..*)',urlResults,re.DOTALL|re.MULTILINE)

    print "Finished retrieving " +str(len(openPhishURL_formatted))+ " Open Phish URLs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(openPhishURL_formatted))
    lf.write('\nRetrieved ' + str(len(openPhishURL_formatted)) + ' Open Phish URLs.')


def parseMalwareDomainList(urlResults):

    malwareDomain = ['']

    n = re.findall('127\.0\.0\.1(.*?)^127\.0\.0\.1',urlResults,re.DOTALL|re.MULTILINE)

    malwareDomain_formatted = ['']

    x=0

    for y in n:
        if len(y) > 1:
            malwareDomain.append(('dest=' + n[x].strip().strip('\n') + ' threat_list_name=Malware_Domains').strip('\n') )
        x=x+1
    print "Finished retrieving " +str(len(malwareDomain))+ " Malware Domains."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(malwareDomain))
    lf.write('\nRetrieved ' + str(len(malwareDomain)) + ' Malware Domains.')

def parseISCSANSSuspiciousDomainsList(urlResults):

    ISCSANSSuspiciousDomain = ['']
    ISCSANSSuspiciousDomain_formatted = ['']
    #print "ISCSANS: " + urlResults

    ISCSANSSuspiciousDomain = urlResults.split('Site\n')
    if len(ISCSANSSuspiciousDomain)>0:
        ISCSANSSuspiciousDomain = ISCSANSSuspiciousDomain[1].split('\n')

        for domain in ISCSANSSuspiciousDomain[:-11]:
            ISCSANSSuspiciousDomain_formatted.append('dest=' + domain.strip() + ' threat_list_name=ISC_SANS_Suspicious')


    print "Finished retrieving " +str(len(ISCSANSSuspiciousDomain_formatted))+ " ISC SANS Suspicious Domains."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(ISCSANSSuspiciousDomain_formatted))
    lf.write('\nRetrieved ' + str(len(ISCSANSSuspiciousDomain_formatted)) + ' ISC SANS Suspicious Domains.')



def parseHPHostsByMalwarebytesDomainList(urlResults):

    HPHostsByMalwarebytesDomain = ['']


    #HPHostsByMalwarebytesDomain = urlResults.split('!!!!^#')

    #HPHostsByMalwarebytesDomain = HPHostsByMalwarebytesDomain[1].split('\n')

    n = re.findall('127\.0\.0\.1(.*?)^127\.0\.0\.1',urlResults,re.DOTALL|re.MULTILINE)


    HPHostsByMalwarebytesDomain_formatted = ['']

    x=0

    for y in n:
        if len(y) > 1:

            HPHostsByMalwarebytesDomain.append(('dest=' + n[x].strip().strip('\n') + ' threat_list_name=HP_Hosts_By_MalwareBytes').strip('\n') )
            #print 'dest=' + n[x]
        x=x+1

    print "Finished retrieving " +str(len(HPHostsByMalwarebytesDomain))+ " HP Hosts by MalwareBytes Domains."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    hphosts_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    hphosts_lf.write( "\n".join(HPHostsByMalwarebytesDomain))
    lf.write('\nRetrieved ' + str(len(HPHostsByMalwarebytesDomain)) + ' HP Hosts by MalwareBytes Domains')

def parseMalc0deDomains(urlResults):
    malcodeDomains = ['']
    line_split = ""

    malcodeDomains_formatted = ['']

    malcodeDomains = urlResults.split("\n")

    for line in malcodeDomains:
        if (len(line) > 5):
            line_split = line.split('\"')
        if (len(line_split) > 1):
            malcodeDomains_formatted.append("dest=" + line_split[1] + " threat_list_name=malc0de_Domains")

    print "Finished retrieving " + str(len(malcodeDomains_formatted)) + " Malc0de Domains."
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(malcodeDomains_formatted))
    lf.write('\nRetrieved ' + str(len(malcodeDomains_formatted)) + ' Malc0de Domains.')


def parseTorBlockList(urlResults):

    torExitNodeIPs = ['']

    m = re.findall('^ExitNode (.*?)^Published',urlResults,re.DOTALL|re.MULTILINE)
    n = re.findall('^LastStatus (.*?)^ExitAddress',urlResults,re.DOTALL|re.MULTILINE)
    o = re.findall('^ExitAddress (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) ',urlResults,re.DOTALL|re.MULTILINE)

    x=0


    for y in m:
        if len(y) > 1:
            torExitNodeIPs.append(('dest_ip=' + o[x] + ' threat_list_name=TorExitNodes last_status_date=\'' + n[x].strip('\n') + '\' ' + 'exit_node_id=' + m[x] ).strip('\n') )
        x=x+1

    #print torExitNodeIPs
    print "Finished retrieving " +str(len(torExitNodeIPs))+ " TorExitNodes."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(torExitNodeIPs))
    lf.write('\nRetrieved ' + str(len(torExitNodeIPs)) + ' IPs from TorExitNodes')


def parseOpenBL(urlResults):


    openBLIPs = urlResults.split('# source ip')

    openBLIPs = openBLIPs[1].split('\n')

    openBLIPs_formatted = ['']


    for ip in openBLIPs:
        openBLIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=OpenBL_1day')


    print "Finished retrieving " + str(len(openBLIPs)) + " IPs from Open Blocklist base 1 day."
    #of.write(zeusIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(openBLIPs_formatted))
    lf.write('\nRetrieved ' + str(len(openBLIPs)) + ' IPs from Open Blocklist base 1 day.')

def parseZeus(urlResults):


    zeusIPs = urlResults.split('##############################################################################')

    zeusIPs = zeusIPs[2].split('\n')

    zeusIPs_formatted = ['']


    for ip in zeusIPs:
        zeusIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Zeus')


    print "Finished retrieving " + str(len(zeusIPs)) + " IPs from Zeus."
    #of.write(zeusIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(zeusIPs_formatted))
    lf.write('\nRetrieved ' + str(len(zeusIPs)) + ' IPs from Zeus')



def parseEmergingThreatsBlockList(urlResults):
    m = re.findall('^#Spamhaus DROP Nets(.*?)^#Dshield Top Attackers',urlResults,re.DOTALL|re.MULTILINE)

    spamHausIPs = m[0].split()
    #print spamHausIPs
    spamHausIPs_formatted = ['']

    for ip in spamHausIPs:
        if len(ip) > 1:
            spamHausIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Spamhaus_Drop_Nets')


    #print spamHausIPs_formatted
    print "Finished retrieving " + str(len(spamHausIPs)) + " IPs from SpamHaus."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(spamHausIPs_formatted))
    lf.write('\nRetrieved ' + str(len(spamHausIPs)) + ' IPs from SpamHaus')


    dshieldIPs = urlResults.split('#Dshield Top Attackers')

    dshieldIPs = dshieldIPs[1].split('\n')

    dshieldIPs_formatted = ['']

    for ip in dshieldIPs:
        if len(ip) > 1:
            dshieldIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Dshield_Top_Attackers')


    print "Finished retrieving " + str(len(dshieldIPs)) + " IPs from Dshield."
    #of.write(dshieldIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(dshieldIPs_formatted))
    lf.write('\nRetrieved ' + str(len(dshieldIPs)) + ' IPs from Dshield')
    ###############################



    ###############################
    p = re.findall('^# Feodo(.*?)^# Zeus',urlResults,re.DOTALL|re.MULTILINE)


    feodoIPs = p[0].split()
    #print spamHausIPs
    feodoIPs_formatted = ['']

    for ip in feodoIPs:
        if len(ip) > 1:
            feodoIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Feodo')


    print "Finished retrieving "+ str(len(feodoIPs))  + " IPs from Feodo."
    #of.write(feodoIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(feodoIPs_formatted))
    lf.write('\nRetrieved ' + str(len(feodoIPs)) + ' IPs from Feodo')
    ########################

def parseEmergingThreatsCompromisedIPs(urlResults):
    compromisedIPs = urlResults.split()
    compromisedIPs_formatted = ['']

    for ip in compromisedIPs:
        if len(ip) > 1:
            compromisedIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Emerging_Threats_Compromised_IPs')


    print "Finished retrieving "+ str(len(compromisedIPs))  +" Emerging Threats Compromised IPs."
    #of.write(compromisedIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(compromisedIPs_formatted))
    lf.write('\nRetrieved ' + str(len(compromisedIPs)) + ' IPs from Emerging Threats Compromised IPs')

    #************************************

def parseBinaryDefenseIPs(urlResults):
    ###############################

    binaryDefenseIPs = urlResults.split('#\n#\n#\n')

    #print binaryDefenseIPs

    binaryDefenseIPs = binaryDefenseIPs[2].split('\n')
    #binaryDefenseIPs = binaryDefenseIPs[1].split('\n')

    binaryDefenseIPs_formatted = ['']

    for ip in  binaryDefenseIPs:
        if len(ip) > 1:
            binaryDefenseIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Binary_Defense_IPs')


    print "Finished retrieving "+ str(len(binaryDefenseIPs)) +" IPs from Binary Defense."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    binarydefense_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    binarydefense_lf.write( "\n".join(binaryDefenseIPs_formatted))
    lf.write('\nRetrieved ' + str(len(binaryDefenseIPs)) + ' IPs from Binary Defense')

    #************************************

def parseAbuseCHSSLIPBLIPs(urlResults):
    Abuse_CH_SSL_IPBLIPs = urlResults.split('# DstIP,DstPort')

    Abuse_CH_SSL_IPBLIPs =  Abuse_CH_SSL_IPBLIPs[1].split('\n')

    #Abuse_CH_SSL_IPBLIPs.pop()
    Abuse_CH_SSL_IPBLIPs = Abuse_CH_SSL_IPBLIPs[1:]

    #print "abuses: " + str(Abuse_CH_SSL_IPBLIPs)

    Abuse_CH_SSL_IPBLIPs_formatted = ['']

    for ip in  Abuse_CH_SSL_IPBLIPs:
        #print "ip: " + ip

        if len(ip) > 1:
            if (len((str(ip)).split(',')) ==3 ):
                ip_addr,ssl_port,threat_desc = (str(ip)).split(',')

                threat_desc_no_spaces =re.sub(r' ', '_', threat_desc)
                #new_string = re.sub(r'"(\d+),(\d+)"', r'\1.\2', original_string)
                #lines.append((ip_addr,ssl_port,threat_type))

                Abuse_CH_SSL_IPBLIPs_formatted.append('dest_ip=' + ip_addr + ' dest_port=' + ssl_port + ' threat_description=' + threat_desc_no_spaces + ' threat_list_name=Abuse_CH_SSL_IP_Blocklist')
                 #binaryDefenseIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=Abuse_CH_SSL_IPBL_IPs')


    #print "Finished retrieving Abuse_CH_SSL_IPBL."
    of.write(Abuse_CH_SSL_IPBLIPs_formatted)
    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(Abuse_CH_SSL_IPBLIPs_formatted))
    lf.write('\nRetrieved ' + str(len(Abuse_CH_SSL_IPBLIPs)) + ' IPs from Abuse_CH_SSL_IPBL')


    #************************************

def parseMalc0deIPs(urlResults):
    malc0deIPs = urlResults.split('\n\n')

    malc0deIPs =  malc0deIPs[1].split('\n')

    malc0deIPs_formatted = ['']

    for ip in  malc0deIPs:
        if len(ip) > 1:
            malc0deIPs_formatted.append('dest_ip=' + ip + ' threat_list_name=malc0de_IPs')


    print "Finished retrieving "+ str(len(malc0deIPs)) +" malc0de_IPs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(malc0deIPs_formatted))
    lf.write('\nRetrieved ' + str(len(malc0deIPs)) + ' IPs from malc0de_IPs')

    #************************************

def parseAlienVault(urlResults):
    #urlResults=usock.read()
    ###############################

    AlienVaultIPs = urlResults.split('# Generic format')

    AlienVaultIPs =  AlienVaultIPs[1].split('\n')

    AlienVaultIPs_formatted = ['']

    for ip in  AlienVaultIPs:
        if len(ip) > 1:

            ip_addr,metadata =(str(ip)).split('#')

            threat_desc,region,latitude,longitude=(str(metadata)).split(',')

            threat_desc_no_spaces =re.sub(r' ', '_', threat_desc)
            threat_desc_no_spaces =re.sub(r';', '_and_', threat_desc_no_spaces)
            region_no_spaces =re.sub(r' ', '_', region)


            AlienVaultIPs_formatted.append('dest_ip=' + ip_addr + ' threat_description=' + threat_desc_no_spaces + ' region='+ region_no_spaces + ' latitude=' + latitude + ' longitude='+longitude+' threat_list_name=AlienVault_IP_Blocklist')


    print "Finished retrieving "+ str(len(AlienVaultIPs)) +" IPs from AlienVault."
    #of.write(AlienVaultIPs_formatted)

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    alienvault_lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    alienvault_lf.write( "\n".join(AlienVaultIPs_formatted))
    lf.write('\nRetrieved ' + str(len(AlienVaultIPs)) + ' IPs from AlienVaultIPs')

def parseAutoshunIPs(urlResults):
    autoshunIPs = urlResults.split('\n')

    #autoshunIPs =  autoshunIPs[1].split('\n')

    autoshunIPs_formatted = ['']

    threat_desc_no_spaces = ''

    for line in autoshunIPs:
        if len(line) > 5:
            line_split = line.split(',')
        if (len(line_split) > 2):
        #print "line_split0: " + line_split[0]
        #print "line_split2: " + line_split[2]
            threat_desc_no_spaces =re.sub(r' ', '_', line_split[2])
            autoshunIPs_formatted.append("dest_ip=" + line_split[0] + " threat_list_name=autoshun_IPs threat_description=" + threat_desc_no_spaces)


    print "Finished retrieving "+ str(len(autoshunIPs)) +" AutoShun IPs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(autoshunIPs_formatted))
    lf.write('\nRetrieved ' + str(len(autoshunIPs)) + ' IPs from AutoShun IPs')

def parseCI_Army_BadguysIPs(urlResults):
    CI_Army_Badguys_IPs = urlResults.split('\n')

    CI_Army_Badguys_IPs_formatted = ['']


    for line in CI_Army_Badguys_IPs:
        if len(line) > 5:
            line_split = line.split('.')
        #print "len_line_split:" + str(len(line_split))
        if (len(line_split) > 3):
        #threat_desc_no_spaces =re.sub(r' ', '_', line_split[2])
            CI_Army_Badguys_IPs_formatted.append("dest_ip=" + line + " threat_list_name=CI_Army_Badguys_IPs")


    print "Finished retrieving "+ str(len(CI_Army_Badguys_IPs)) +" CI Army Badguys IPs."

    lf.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write('\nThreat list written to at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT')
    of.write( "\n".join(CI_Army_Badguys_IPs_formatted))
    lf.write('\nRetrieved ' + str(len(CI_Army_Badguys_IPs)) + ' IPs from CI Army Badguys')

    #************************************

def main():


    lf.write('[*] Script Started at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    of.write('[*] Script Started at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n')
    lf.write('[*] Script version: ' + script_version + '\n')
    print '[*] Script Started at: ' + strftime("%m-%d-%Y %H:%M:%S", gmtime()) + ' GMT\n'

    print '[*] Script version: ' + script_version
    raw_threatlist = ""


    raw_threatlist = getUrl(urlList[0].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseEmergingThreatsBlockList(raw_threatlist)

    raw_threatlist = getUrl(urlList[1].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseEmergingThreatsCompromisedIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[5].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseMalc0deIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[3].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseAlienVault(raw_threatlist)

    raw_threatlist = getUrl(urlList[6].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseTorBlockList(raw_threatlist)

    #raw_threatlist = getUrl(urlList[4].strip('\n'),'true')
    #if len(str(raw_threatlist)) > 3:
    #    parseZeus(raw_threatlist)

    raw_threatlist = getUrl(urlList[8].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseHPHostsByMalwarebytesDomainList(raw_threatlist)

    raw_threatlist = getUrl(urlList[11].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseMalwareDomainList(raw_threatlist)

    raw_threatlist = getUrl(urlList[10].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseISCSANSSuspiciousDomainsList(raw_threatlist)

    raw_threatlist = getUrl(urlList[12].strip('\n'),'false')
    if len(str(raw_threatlist)) > 3:
        parseOpenPhishURLList(raw_threatlist)

    raw_threatlist = getUrl(urlList[13].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parsePhishTankURLList(raw_threatlist)

    raw_threatlist = getUrl(urlList[14].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseBambenekconsultingIPList(raw_threatlist)

    raw_threatlist = getUrl(urlList[15].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseTalosIntel(raw_threatlist)

    raw_threatlist = getUrl(urlList[16].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseMalc0deDomains(raw_threatlist)

    raw_threatlist = getUrl(urlList[17].strip('\n'),'false')

    if len(str(raw_threatlist)) > 3:
         parseCI_Army_BadguysIPs(raw_threatlist)

    raw_threatlist = getUrl(urlList[18].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseRansomwareAbuseCHIPlist(raw_threatlist)

    raw_threatlist = getUrl(urlList[19].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseRansomwareAbuseCHDomainlist(raw_threatlist)

    raw_threatlist = getUrl(urlList[20].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseRansomwareAbuseCHURLlist(raw_threatlist)

    raw_threatlist = getUrl(urlList[21].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseNoThinkSSHBlacklist(raw_threatlist)

    raw_threatlist = getUrl(urlList[22].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseBlocklistde(raw_threatlist)

    raw_threatlist = getUrl(urlList[23].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseDarklistde(raw_threatlist)

    raw_threatlist = getUrl(urlList[24].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseJoeWein(raw_threatlist)
  
    raw_threatlist = getUrl(urlList[25].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseGreenSnow(raw_threatlist)

    raw_threatlist = getUrl(urlList[26].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseSpysProxy(raw_threatlist)

    raw_threatlist = getUrl(urlList[27].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseBadIPsList(raw_threatlist)

    #parseTeamCymruBogonCIDRlist
    raw_threatlist = getUrl(urlList[28].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
         parseSocksProxyIPlist(raw_threatlist)

    raw_threatlist = getUrl(urlList[29].strip('\n'),'true')
    if len(str(raw_threatlist)) > 3:
        parseTeamCymruBogonCIDRlist(raw_threatlist)


if __name__ == '__main__':
    main()
