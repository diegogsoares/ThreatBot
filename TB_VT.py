from TB_Logger import *
import requests
import sys

######################################################
##########
########## Variables Virus Total APIs
##########
######################################################
import credential

VT_DOMAIN_URL = "https://www.virustotal.com/vtapi/v2/domain/report?"
VT_IP_URL = "http://www.virustotal.com/vtapi/v2/ip-address/report?"
VT_HASH_URL = "https://www.virustotal.com/vtapi/v2/file/report?"
VT_HEADERS = {"Accept-Encoding": "gzip, deflate",
              "User-Agent": "gzip,  My Python requests library example client or username"}

######################################################
##########
########## Function CHECK IP Virus Total
##########
######################################################
def CHECK_IP_VT (input_value):

    VT_IP_PARAMTERS={'ip': input_value, 'apikey': credential.vt_accessToken}
    resp_ip_vt = requests.get(VT_IP_URL, params=VT_IP_PARAMTERS)

    if resp_ip_vt.status_code != 200:
        logger.info("IP VT FAIL! -  " + str(resp_ip_vt.status_code))
        return "VirusTotal Error: API Call Status " + str(resp_ip_vt.status_code)

    resp_ip_vt_json = resp_ip_vt.json()

    if resp_ip_vt_json.get("response_code") == 0:
        return 'No information was found on '+input_value


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

    print_msg = "This IP Address hosts " + str(ip_url_count) + " malicious URLs and " + str(ip_samples_count) + " malicious Files!\n"
    print_msg = print_msg + " More information @ https://virustotal.com/en/ip-address/" + input_value + "/information\n"

    logger.info("VT HASH OK!")
    print("VT HASH OK!")

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
        logger.info("Domain VT FAIL! -  " + str(resp_domain_vt.status_code))
        return "VirusTotal Error: API Call Status " + str(resp_domain_vt.status_code)

    resp_domain_vt_json = resp_domain_vt.json()

    if resp_domain_vt_json.get("response_code") == 0:
        return 'No information was found on '+input_value

#    print(json.dumps(resp_domain_vt_json, indent=4, separators=(',', ': ')))

    security_category = resp_domain_vt_json.get("categories")
    print_msg = " " + input_value + " is categorized as " + str(security_category) + "\n"

    url = "http://"+input_value+"/"
    for i in resp_domain_vt_json["detected_urls"]:
        if i['url'] == url:
            print_msg = print_msg + " "+ str(i['positives']) + " where found bad out of " + str(i['total']) + "\n"
    print_msg = print_msg + " More information @ https://virustotal.com/en/domain/" + input_value + "/information\n"

    logger.info("VT HASH OK!")
    print("VT HASH OK!")

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
        logger.info("HASH VT FAIL! -  " + str(resp_hash_vt.status_code))
        return "VirusTotal Error: API Call Status " + str(resp_hash_vt.status_code)

    resp_hash_vt_json = resp_hash_vt.json()

    if resp_hash_vt_json.get("response_code") == 0:
        return "No information was found on this file!"

#    print(json.dumps(resp_hash_vt_json, indent=4, separators=(',', ': ')))

    vt_hash_totals = resp_hash_vt_json.get("total")
    vt_hash_positives = resp_hash_vt_json.get("positives")
    vt_clamav = resp_hash_vt_json.get("scans").get("ClamAV").get("detected")
    vt_clamav_name = resp_hash_vt_json.get("scans").get("ClamAV").get("result")

    print_msg = "We found " + str(vt_hash_positives) + " positive hits out of " + str(vt_hash_totals) + " scans!\n"

    if vt_clamav == True:
        print_msg = print_msg + "   ClamAV has detected this hash as " + vt_clamav_name + "\n"

    print_msg = print_msg + " More information @ https://virustotal.com/en/file/" + resp_hash_vt_json.get("sha256") + "/analysis\n"

    logger.info("VT HASH OK!")
    print("VT HASH OK!")


    return print_msg

######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

if sys.argv[1] == '-ip':
    msg_to_print = CHECK_IP_VT(sys.argv[2])
    print (msg_to_print)
elif sys.argv[1] == '-hash':
    msg_to_print = CHECK_HASH_VT(sys.argv[2])
    print(msg_to_print)
elif sys.argv[1] == '-domain':
    msg_to_print = CHECK_DOMAIN_VT(sys.argv[2])
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''