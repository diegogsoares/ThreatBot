import json
import requests
import validators
from itty import *
import urllib2
import logging
import dns.resolver
import sys

requests.packages.urllib3.disable_warnings()

###
### Next feeds:
### Talos Intel - amptools.cisco.com
### Bright Cloud
### mxtoolbox.com/SuperTool.aspx#
### Stealthwatch flows for domain + IPs
### FMC for domain + IPs
###

######################################################
##########
########## Variabbles
##########
######################################################
### Import credentials
import credential

### API URLs - ODNS
investigate_header = {'Authorization': 'Bearer ' + credential.odns_accessToken}
odns_uri = 'https://investigate.api.umbrella.com/'
odns_category_url = 'domains/categorization/'
odns_secscore_url = 'security/name/'
odns_samples_url = 'samples/'
odns_sample_info_url = 'sample/'

### API URLs - VirusTotal
VT_DOMAIN_URL = "https://www.virustotal.com/vtapi/v2/domain/report?"
VT_IP_URL = "http://www.virustotal.com/vtapi/v2/ip-address/report?"
VT_HASH_URL = "https://www.virustotal.com/vtapi/v2/file/report?"
VT_HEADERS = {"Accept-Encoding": "gzip, deflate", "User-Agent": "gzip,  My Python requests library example client or username"}

### API URLs - AMP
amp_header = {'Authorization': 'Basic ' + credential.amp_auth_token,'Content-Type': 'application/json', 'Accept': 'application/json'}
amp_url = 'https://api.amp.cisco.com'
amp_url_pc = 'https://api.amp.cisco.com/v1/computers/activity?q='
amp_url_hash = 'https://api.amp.cisco.com/v1/events?application_sha256='

### API URLs - ThreatGrid
tg_url = 'https://panacea.threatgrid.com/api/v2/'

### DNS Blacklists
bls = ["zen.spamhaus.org", "spam.abuse.ch", "cbl.abuseat.org", "dnsbl.inps.de",
       "ix.dnsbl.manitu.net", "dnsbl.sorbs.net", "bl.spamcannibal.org", "bl.spamcop.net",
       "xbl.spamhaus.org", "pbl.spamhaus.org", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
       "dnsbl-3.uceprotect.net", "db.wpbl.info"]

### LGOGOs
cisco_logo = 'http://www.cisco.com/web/europe/images/email/signature/logo02.jpg'



######################################################
##########
########## Logging Info
##########
######################################################
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# create a file handler
handler = logging.FileHandler('ThreatBot.log')
handler.setLevel(logging.INFO)

# create a logging format
formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)

# add the handlers to the logger
logger.addHandler(handler)


######################################################
##########
########## Check SPAM Blacklist
##########
######################################################
def CHECK_SPAM_BL (input_value,input):

    print_msg = '\n@SPAM Blacklist:\n'
    loop_count = loop_count_1 = 0
    mxservers = []

    if input == 'ip':
        for bl in bls:
            try:
                my_resolver = dns.resolver.Resolver()
                query = '.'.join(reversed(str(input_value).split("."))) + "." + bl
                answers = my_resolver.query(query, "A")
#                answer_txt = my_resolver.query(query, "TXT")
                if loop_count_1 == 0:
                    print_msg = print_msg + 'IP: ' + input_value + ' IS listed in ' + bl
                    loop_count_1 += 1
                else:
                    print_msg = print_msg + ', ' + bl
            except dns.resolver.NXDOMAIN:
                loop_count += 1
        if loop_count > 0:
            print_msg = print_msg + 'IP not listed in ' + str(loop_count) + ' Blacklists'

    else:
        try:
            my_resolver = dns.resolver.Resolver()
            answers = my_resolver.query(input_value, "MX")
            for mx_server in answers:
                weigth, mail_server = str(mx_server).split(" ")
                my_resolver1 = dns.resolver.Resolver()
                mx_ip = my_resolver1.query(mail_server, "A")
                mxservers.append(mx_ip[0])
        except dns.resolver.NXDOMAIN:
            return "\n@SPAM Blacklist: This domain does not have a MX Record."
        except dns.resolver.NoAnswer:
            return "\n@SPAM Blacklist: This domain does not have a MX Record."

        count_ip = count_ip_yes = count_bl = count_yes = count_no = 0
        for server_ip in mxservers:
            count_ip += 1
            count_bl = count_yes = count_no = 0

            for bl in bls:
                count_bl += 1
                try:
                    my_resolver = dns.resolver.Resolver()
                    query = '.'.join(reversed(str(server_ip).split("."))) + "." + bl
                    answers = my_resolver.query(query, "A")
                    count_yes += 1
                except dns.resolver.NXDOMAIN:
                    count_no += 1

            if count_yes >> 0:
                count_ip_yes += 1
        print_msg = print_msg + 'Domain: %s has %s MX Servers found in %s Blacklists!' % (input_value, count_ip, count_ip_yes)

    logger.info("SPAM BL OK!")

    return print_msg

######################################################
##########
########## Function CHECK Investigate
##########
######################################################
def CHECK_DOMAIN_ODNS (input_value):

    resp_category = requests.get(odns_uri + odns_category_url + input_value + "?showLabels", headers=investigate_header)
    resp_secscore = requests.get(odns_uri + odns_secscore_url + input_value + ".json", headers=investigate_header)
    resp_samples = requests.get(odns_uri + odns_samples_url + input_value, headers=investigate_header)

    if resp_category.status_code != 200:
        return "Umbrella Error: API Call Status " + str(resp_category.status_code)

    if resp_secscore.status_code != 200:
        return "Umbrella Error: API Call Status " + str(resp_secscore.status_code)

    if resp_samples.status_code != 200:
        return "Umbrella Error: API Call Status " + str(resp_samples.status_code)

    resp_category_json=resp_category.json()
    resp_secscore_json=resp_secscore.json()
    resp_samples_json=resp_samples.json()

    secure_score = str(resp_secscore_json.get("securerank2"))
    rip_score = str(resp_secscore_json.get("rip_score"))

    if resp_category_json[input_value]["status"] == -1:
        security_category = ""
        for i in resp_category_json[input_value]["security_categories"]:
            security_category +=  i + ", "
        print_msg = "@OpenDNS " + input_value + " is categorized as " + security_category + "and is in the Block List!\n It's security score is: " + secure_score + "\n It' IP reputation is: " + rip_score + "\n"

        if resp_samples_json["totalResults"] > 0:
            print_msg = print_msg + " It has " + str(resp_samples_json["totalResults"]) + " malware samples, some listed below:" + "\n"
            loop_count = 1
            for ii in resp_samples_json["samples"]:
                if loop_count <= 5:
                    print_msg = print_msg + "\t" + ii["sha1"] + " - Threat Score (" + str(ii["threatScore"]) + ")" + "\t - https://investigate.opendns.com/sample-view/" + ii["sha1"] + "\n"
                    loop_count += 1

        print_msg = print_msg + "More information @ https://investigate.opendns.com/domain-view/name/"+input_value+'/view' + "\n"

    elif resp_category_json[input_value]["status"] == 1:
        security_category = ""
        for i in resp_category_json[input_value]["content_categories"]:
            security_category +=  i + ", "
        print_msg = "@OpenDNS " + input_value + " is categorized as " + security_category + "and is Good!\n It's security score is: " + secure_score + "\n It's IP reputation is: " + rip_score + "\n"

        if resp_samples_json["totalResults"] > 0:
            print_msg = print_msg + " It has " + str(resp_samples_json["totalResults"]) + " malware samples, some listed below:" + "\n"
            loop_count = 1
            for ii in resp_samples_json["samples"]:
                if loop_count <=5:
                    print_msg = print_msg + "\t" + ii["sha1"] + " - Threat Score (" + str(ii["threatScore"]) + ")" + "\t - https://investigate.opendns.com/sample-view/" + ii["sha1"] + "\n"
                    loop_count += 1

        print_msg = print_msg + "More information @ https://investigate.opendns.com/domain-view/name/"+input_value+'/view' + "\n"

    else:
        print_msg = "@OpenDNS " + input_value + " is Unclassified!\n It's security score is: " + secure_score + "\n It's IP reputation is: " + rip_score + "\n"

        if resp_samples_json.get("totalResults"):
            totalresults = str(resp_samples_json.get("totalResults"))
        else:
            totalresults = 0

        if totalresults > 0:
            print_msg = print_msg + " It has " + str(resp_samples_json["totalResults"]) + " malware samples, some listed below:" + "\n"
            loop_count = 1
            for ii in resp_samples_json["samples"]:
                if loop_count <= 5:
                    print_msg = print_msg + "\t" + ii["sha1"] + " - Threat Score (" + str(ii["threatScore"]) + ")" + "\t - https://investigate.opendns.com/sample-view/" + ii["sha1"] + "\n"
                    loop_count += 1

        print_msg = print_msg + "More information @ https://investigate.opendns.com/domain-view/name/"+input_value+'/view' + "\n"

    logger.info("ONDS OK!")

    return print_msg

######################################################
##########
########## Function CHECK HASH Investigate
##########
######################################################
def CHECK_HASH_ODNS (input_value):

    resp_hash = requests.get(odns_uri + odns_sample_info_url + input_value, headers=investigate_header)

    if resp_hash.status_code != 200:
        return "Umbrella Error: API Call Status " + str(resp_hash.status_code)

    resp_hash_json = resp_hash.json()

#    print(json.dumps(resp_hash_json, indent=4, separators=(',', ': ')))

    if resp_hash_json.get("error"):
        return "@ Cisco Umbrella NO information was found on this file!\n"

    odns_hash_threatscore = resp_hash_json.get("threatScore")
    odns_hash_type = resp_hash_json.get("magicType")

    print_msg = "@OpenDNS " + str(input_value) + " was classified as " + str(odns_hash_type) + " with a threat score of " + str(odns_hash_threatscore) + "!\n\t These are the connections seen by ThreatGrid:\n"
    for i in resp_hash_json["connections"]['connections']:
        print_msg = print_msg + "\t\t" + i['name'] + "\n"
    print_msg = print_msg + " More information @ https://investigate.umbrella.com/sample-view/" + input_value + "\n"

    logger.info("ONDS OK!")

    return print_msg

######################################################
##########
########## Function CHECK IP Virus Total
##########
######################################################
def CHECK_IP_VT (input_value):

    VT_IP_PARAMTERS={'ip': input_value, 'apikey': credential.vt_accessToken}
    resp_ip_vt = requests.get(VT_IP_URL, params=VT_IP_PARAMTERS)

    if resp_ip_vt.status_code != 200:
        return "VirusTotal Error: API Call Status " + str(resp_ip_vt.status_code)

    resp_ip_vt_json = resp_ip_vt.json()

    if resp_ip_vt_json['response_code'] == 0:
        return '\n@VirusTotal no information was found on '+input_value


#    print(json.dumps(resp_ip_vt_json, indent=4, separators=(',', ': ')))
    ip_url_count = 0
    ip_samples_count = 0

    for i in resp_ip_vt_json["detected_urls"]:
        if i['positives'] >= 5:
            ip_url_count=ip_url_count+1

    if resp_ip_vt_json.get("detected_downloaded_samples"):
        for ii in resp_ip_vt_json["detected_downloaded_samples"]:
            if ii['positives'] >= 5:
                ip_samples_count=ip_samples_count+1

    print_msg = "\n@VirusTotal this IP Address hosts " + str(ip_url_count) + " malicious URLs and " + str(ip_samples_count) + " malicious Files!\n"
    print_msg = print_msg + " More information @ https://virustotal.com/en/ip-address/" + input_value + "/information\n"

    logger.info("VT OK!")

    return print_msg

######################################################
##########
########## Function CHECK DOMAIN Virus Total
##########
######################################################
def CHECK_DOMAIN_VT (input_value):

    VT_DOMAIN_PARAMTERS={'domain': input_value, 'apikey': credential.vt_accessToken}
    resp_domain_vt = requests.get(VT_DOMAIN_URL, params=VT_DOMAIN_PARAMTERS, verify=False)

    if resp_domain_vt.status_code != 200:
        return "VirusTotal Error: API Call Status " + str(resp_domain_vt.status_code)

    resp_domain_vt_json = resp_domain_vt.json()

#    print(json.dumps(resp_domain_vt_json, indent=4, separators=(',', ': ')))

    security_category = resp_domain_vt_json.get("categories")
    print_msg = "\n@VirusTotal " + input_value + " is categorized as " + str(security_category) + "\n"

    url = "http://"+input_value+"/"
    for i in resp_domain_vt_json["detected_urls"]:
        if i['url'] == url:
            print_msg = print_msg + " "+ str(i['positives']) + " where found bad out of " + str(i['total']) + "\n"
    print_msg = print_msg + " More information @ https://virustotal.com/en/domain/" + input_value + "/information\n"

    logger.info("VT OK!")

    return print_msg

######################################################
##########
########## Function CHECK HASH Virus Total
##########
######################################################
def CHECK_HASH_VT (input_value):

    VT_HASH_PARAMTERS={'apikey': credential.vt_accessToken, 'resource': input_value}
    resp_hash_vt = requests.post(VT_HASH_URL, headers=VT_HEADERS, params=VT_HASH_PARAMTERS)

    if resp_hash_vt.status_code != 200:
        return "VirusTotal Error: API Call Status " + str(resp_hash_vt.status_code)

    resp_hash_vt_json = resp_hash_vt.json()

    if resp_hash_vt_json.get("response_code") == 0:
        return "\n@VirusTotal has no information on this file!"

#    print(json.dumps(resp_hash_vt_json, indent=4, separators=(',', ': ')))

    vt_hash_totals = resp_hash_vt_json.get("total")
    vt_hash_positives = resp_hash_vt_json.get("positives")
    vt_clamav = resp_hash_vt_json.get("scans").get("ClamAV").get("detected")
    vt_clamav_name = resp_hash_vt_json.get("scans").get("ClamAV").get("result")

    print_msg = "\n@VirusTotal found " + str(vt_hash_positives) + " positive hits out of " + str(vt_hash_totals) + " scans!\n"

    if vt_clamav == True:
        print_msg = print_msg + "   ClamAV has detected this hash as " + vt_clamav_name + "\n"

    print_msg = print_msg + " More information @ https://virustotal.com/en/file/" + resp_hash_vt_json.get("sha256") + "/analysis\n"

    logger.info("VT OK!")

    return print_msg

######################################################
##########
########## Function CHECK IP ThreatGrid
##########
######################################################
def CHECK_QUERY_TG (input_value,input):

    parameters_ip_tg='api_key='+credential.tg_apikey+'&q='+input_value+'&limit=50'
    resp_ip_tg = requests.get(tg_url+'search/submissions?', params=parameters_ip_tg)

    if resp_ip_tg.status_code != 200:
        return "ThreatGrig Error: API Call Status " + str(resp_ip_tg.status_code)

    resp_ip_tg_json = resp_ip_tg.json()

#    print(json.dumps(resp_ip_tg_json, indent=4, separators=(',', ': ')))

    samples_tg_count = str(resp_ip_tg_json['data']['current_item_count'])

    if resp_ip_tg_json['data']['current_item_count'] == 0:
        print_msg = "\n@ThreatGrid no information was found on " + input_value + "\n"
    else:
        print_msg = "\n@ThreatGrid found " + samples_tg_count + " Malware Samples!\n\tThis is/are some sample(s) found:\n"

    loop_count =1

    for i in resp_ip_tg_json["data"]["items"]:
        if loop_count <= 5:
            print_msg = print_msg + "\t\t"+ str(i['item']['sha1']) + " (" + str(i['item']['analysis']['threat_score'])+ ") - https://panacea.threatgrid.com/mask/#/samples/" + i['item']['sample'] + "\n"
            loop_count += 1

    if input == 'ip':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/ips/" + input_value + "\n"
    elif input == "domain":
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/domains/" + input_value + "\n"
    elif input =='hash':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/search/samples?term=freeform&q=" + input_value + "\n"

    logger.info("TG OK!")

    return print_msg

######################################################
##########
########## Function CHECK PC AMP
##########
######################################################
def CHECK_AMP (input_value,type):

    resp_amp = requests.get(amp_url_pc+input_value, headers=amp_header)

    if resp_amp.status_code != 200:
        return "AMP Error: API Call Status " + str(resp_amp.status_code)

    resp_amp_json = resp_amp.json()

#    print(json.dumps(resp_amp_json, indent=4, separators=(',', ': ')))

    if type == 'hash256':
        resp_amp_hash = requests.get(amp_url_hash + input_value, headers=amp_header)
        if resp_amp_hash.status_code != 200:
            return "AMP Error: API Call Status " + str(resp_amp_hash.status_code)
        resp_amp_hash_json = resp_amp_hash.json()
        count=0
        if resp_amp_hash_json["data"]:
            for i in resp_amp_hash_json["data"]:
                if count == 0:
                    hash_disposition = str(i["file"]["disposition"])
                    count += 1
        else:
            hash_disposition = None
    else:
        hash_disposition = None

    if hash_disposition != None:
        print_msg = "\n@Cisco AMP file disposition is " + hash_disposition +" and " + str(resp_amp_json['metadata']['results']['total']) + " Connectors that saw this activity!\n\tThis are/were the connector(s):\n"
    else:
        if resp_amp_json['metadata']['results']['total'] != 0:
            print_msg = "\n@Cisco AMP found " + str(resp_amp_json['metadata']['results']['total']) + " Connectors that saw this activity!\n\tThis are/were the connector(s):\n"
        else:
            print_msg = "\n@Cisco AMP did not find any activity!\n"

    loop_count = 1
    for i in resp_amp_json["data"]:
        if loop_count <=5:
            print_msg = print_msg + '\t\tConnector GUID: ' + str(i['connector_guid']) + " - " +  str(i['links']['computer']) + "\n"
            loop_count += 1

    print_msg = print_msg + "More activity information @ https://console.amp.cisco.com/search?query=" + input_value  + "\nMore about file details @ https://console.amp.cisco.com/file/" + input_value  + "/profile/details"

    logger.info("AMP OK!")

    return print_msg

######################################################
##########
########## Check Talos Block List
##########
######################################################
def TALOS_BLOCK_LIST(input_value):
    talos_bl = False
    datalist = open("ip-filter.blf", "r")
    iplist = datalist.readline()
    talos_count = 0

    while iplist:
        if iplist.strip() == input_value:
            talos_bl = True
        iplist = datalist.readline()
        talos_count += 1

    if talos_bl == True:
        print_msg = "\n@Talos IP block list has %s entries and IP: %s WAS found!" % (talos_count,input_value)
    else:
        print_msg = "\n@Talos IP block list has %s entries and IP: %s was NOT found!" % (talos_count,input_value)

    datalist.close()

    logger.info("TALOS BL OK!")

    return print_msg

######################################################
##########
########## Function Interact with Spark with a Bot
##########
######################################################
def sendSparkGET(url):
    """
    This method is used for:
        -retrieving message text, when the webhook is triggered with a message
            -Getting the username of the person who posted the message if a command is recognized
    """
    request = urllib2.Request(url, headers={"Accept": "application/json", "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + credential.spark_bearer)
    contents = urllib2.urlopen(request).read()
    return contents

def sendSparkPOST(url, data):
    """
        This method is used for:
            -posting a message to the Spark room to confirm that a command was received and processed
    """
    request = urllib2.Request(url, json.dumps(data), headers={"Accept": "application/json", "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + credential.spark_bearer)
    contents = urllib2.urlopen(request).read()

    return contents

######################################################
##########
##########  MENU - Message parsing
##########
######################################################

@post('/')
def index(request):
    """
        When messages come in from the webhook, they are processed here.  The message text needs to be retrieved from Spark,
        using the sendSparkGet() function.  The message text is parsed.  If an expected command is found in the message,
        further actions are taken. i.e.
    """
    webhook = json.loads(request.body)
    print(webhook['data']['id'])
    result = sendSparkGET('https://api.ciscospark.com/v1/messages/{0}'.format(webhook['data']['id']))
    result = json.loads(result)

    msg = None
    validuser = False
    datalist = open("authorized-users.txt", "r")
    userlist = datalist.readline()

    if webhook['data']['personEmail'] != credential.bot_email:

        while userlist:
            if userlist.strip() == webhook['data']['personEmail']:
                validuser = True
            userlist = datalist.readline()

        in_message = result.get('text', '').lower()
        in_message = in_message.replace(credential.bot_name, '')

        logger.info(webhook['data']['personEmail'])
        logger.info(in_message)

        if (validators.domain(in_message) and validuser == True):
            logger.info("DOMAIN!!")
#            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "files": cisco_logo})

            msg_odns = CHECK_DOMAIN_ODNS(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

            msg_tg = CHECK_QUERY_TG(in_message,"domain")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

            msg_amp= CHECK_AMP(in_message   ,"domain")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp})

            msg_vt = CHECK_DOMAIN_VT(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

            msg_bl = CHECK_SPAM_BL(in_message,"domain")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl})

        elif (validators.ipv4(in_message) and validuser == True):
#            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "files": cisco_logo})

            msg_odns = CHECK_DOMAIN_ODNS(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

            msg_tg = CHECK_QUERY_TG(in_message,"ip")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

            msg_amp= CHECK_AMP(in_message,"ip")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp})

            msg_vt = CHECK_IP_VT(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

            msg_bl = CHECK_SPAM_BL(in_message, "ip")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl})

            msg_talos = TALOS_BLOCK_LIST(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_talos})

        elif (len(in_message) == 40 and validuser == True):
            logger.info("SHA1 Hash!!")
#            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "files": cisco_logo})

            msg_odns = CHECK_HASH_ODNS(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

            msg_tg = CHECK_QUERY_TG(in_message,"hash")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

            msg_amp= "\n @Cisco AMP can only search SHA-256 Hashes!"
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp})

            msg_vt = CHECK_HASH_VT(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

        elif (len(in_message) == 64 and validuser == True):
            logger.info("SHA256 Hash!!")
#            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "files": cisco_logo})

            msg_odns = CHECK_HASH_ODNS(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

            msg_tg = CHECK_QUERY_TG(in_message,"hash")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

            msg_amp= CHECK_AMP(in_message,"hash256")
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp})

            msg_vt = CHECK_HASH_VT(in_message)
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})
        elif validuser == True:
            msg = "Invalid input!!\n Use IPs, Domains or Hashes."
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg})
        else:
            msg_mark = "**Unauthorized User!!**\n Please contact Diego Soares disoares@cisco.com to request Access\n"
            msg = "Unauthorized User!! Please contact Diego Soares disoares@cisco.com to request Access"

            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg, "markdown": msg_mark})

    datalist.close()

    return "true"

run_itty(server='wsgiref', host='0.0.0.0', port=10010)