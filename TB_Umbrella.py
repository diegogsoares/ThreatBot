import requests
import sys
from TB_Logger import *

######################################################
##########
########## Variables Umbrella APIs
##########
######################################################
import credential

investigate_header = {'Authorization': 'Bearer ' + credential.odns_accessToken}
odns_uri = 'https://investigate.api.umbrella.com/'
odns_category_url = 'domains/categorization/'
odns_secscore_url = 'security/name/'
odns_samples_url = 'samples/'
odns_sample_info_url = 'sample/'
odns_ip_domains = 'dnsdb/ip/a/'
odns_name_domains = 'dnsdb/name/a/'

######################################################
##########
########## Function CHECK Investigate
##########
######################################################
def CHECK_DOMAIN_ODNS (input_value,type):

    resp_category = requests.get(odns_uri + odns_category_url + input_value + "?showLabels", headers=investigate_header)
    resp_secscore = requests.get(odns_uri + odns_secscore_url + input_value + ".json", headers=investigate_header)
    resp_samples = requests.get(odns_uri + odns_samples_url + input_value, headers=investigate_header)
    resp_ip_domains = requests.get(odns_uri + odns_ip_domains + input_value + ".json", headers=investigate_header)
    resp_name_domains = requests.get(odns_uri + odns_name_domains + input_value + ".json", headers=investigate_header)

    if resp_category.status_code != 200:
        logger.info("Category ONDS FAIL! -  " + str(resp_category.status_code))
        return "Umbrella Error: API Call Status " + str(resp_category.status_code)

    if resp_secscore.status_code != 200:
        logger.info("Sec. Score ONDS FAIL! -  " + str(resp_secscore.status_code))
        return "Umbrella Error: API Call Status " + str(resp_secscore.status_code)

    if resp_samples.status_code != 200:
        logger.info("Samples ONDS FAIL! -  " + str(resp_samples.status_code))
        return "Umbrella Error: API Call Status " + str(resp_samples.status_code)

    if resp_ip_domains.status_code != 200:
        logger.info("Domains for IP ONDS FAIL! -  " + str(resp_ip_domains.status_code))
        return "Umbrella Error: API Call Status " + str(resp_ip_domains.status_code)

    if resp_name_domains.status_code != 200:
        logger.info("Domains for name ONDS FAIL! -  " + str(resp_name_domains.status_code))
        return "Umbrella Error: API Call Status " + str(resp_name_domains.status_code)

    resp_category_json=resp_category.json()
    resp_secscore_json=resp_secscore.json()
    resp_samples_json=resp_samples.json()
    resp_ip_domains_json = resp_ip_domains.json()
    resp_name_domains_json = resp_name_domains.json()

    secure_score = str(resp_secscore_json.get("securerank2"))
    rip_score = str(resp_secscore_json.get("rip_score"))
    popularity_score = str(resp_secscore_json.get("popularity"))

    if resp_category_json[input_value]["status"] == -1:
        security_category = ""
        for i in resp_category_json[input_value]["security_categories"]:
            security_category +=  i + ", "
        print_msg = " " + input_value + " is categorized as " + security_category + "and is Blocked!\n * Security score is: " + secure_score + "\n * It's IP reputation is: " + rip_score + "\n * IP popularity is: " + popularity_score + "\n"

        ### ADD Associated Domains
        if type == 'ip':
            total_domains = int(resp_ip_domains_json.get("features").get("rr_count"))
            if total_domains > 0:
                print_msg = print_msg + "There are " + str(total_domains) + " associated with this ip address, some listed below:\n"
                loop_count = 1
                for iii in resp_ip_domains_json.get("rrs"):
                    if loop_count <= 5:
                        print_msg = print_msg + " * " + iii.get("rr") + " - Type (" + str(iii.get("type")) + ")" + "\n"
                        loop_count += 1
            else:
                print_msg = print_msg + " There is no domains associated with this IP address.\n"
        else:
            if resp_name_domains_json.get("rrs_tf"):
                record_resource = resp_name_domains_json.get("rrs_tf")[0]
                print_msg = print_msg + " Listed below are the Resource record for this domain:\n"
                loop_count = 1
                for iii in record_resource.get("rrs"):
                    if loop_count <= 5:
                        print_msg = print_msg + " * " + iii.get("rr") + " - Type (" + str(iii.get("type")) + ")" + "\n"
                        loop_count += 1
            else:
                print_msg = print_msg + " There is no Resource record for this domain.\n"
        ###

        if resp_samples_json["totalResults"] > 0:
            print_msg = print_msg + " It has " + str(resp_samples_json["totalResults"]) + " malware samples, some listed below:" + "\n"
            loop_count = 1
            for ii in resp_samples_json["samples"]:
                if loop_count <= 5:
                    print_msg = print_msg + " * " + ii["sha1"] + " - Threat Score (" + str(ii["threatScore"]) + ")" + " - https://investigate.opendns.com/sample-view/" + ii["sha1"] + "\n"
                    loop_count += 1

        print_msg = print_msg + "More information @ https://investigate.opendns.com/domain-view/name/"+input_value+'/view' + "\n"

    elif resp_category_json[input_value]["status"] == 1:
        security_category = ""
        for i in resp_category_json[input_value]["content_categories"]:
            security_category +=  i + ", "
        print_msg = " " + input_value + " is categorized as " + security_category + "and is Good!\n * Security score is: " + secure_score + "\n * IP reputation is: " + rip_score + "\n * IP popularity is: " + popularity_score + "\n"

        ### ADD Associated Domains
        if type == 'ip':
            total_domains = int(resp_ip_domains_json.get("features").get("rr_count"))
            if total_domains > 0:
                print_msg = print_msg + " There are " + str(total_domains) + " associated with this ip address, some listed below:\n"
                loop_count = 1
                for iii in resp_ip_domains_json.get("rrs"):
                    if loop_count <= 5:
                        print_msg = print_msg + " * " + iii.get("rr") + " - Type (" + str(iii.get("type")) + ")" + "\n"
                        loop_count += 1
            else:
                print_msg = print_msg + " There is no domains associated with this IP address.\n"
        else:
            if resp_name_domains_json.get("rrs_tf"):
                record_resource = resp_name_domains_json.get("rrs_tf")[0]
                print_msg = print_msg + " Listed below are the Resource record for this domain:\n"
                loop_count = 1
                for iii in record_resource.get("rrs"):
                    if loop_count <= 5:
                        print_msg = print_msg + " * " + iii.get("rr") + " - Type (" + str(iii.get("type")) + ")" + "\n"
                        loop_count += 1
            else:
                print_msg = print_msg + " There is no Resource record for this domain.\n"
        ###

        if resp_samples_json["totalResults"] > 0:
            print_msg = print_msg + " It has " + str(resp_samples_json["totalResults"]) + " malware samples, some listed below:" + "\n"
            loop_count = 1
            for ii in resp_samples_json["samples"]:
                if loop_count <=5:
                    print_msg = print_msg + " * " + ii["sha1"] + " - Threat Score (" + str(ii["threatScore"]) + ")" + "\t - https://investigate.opendns.com/sample-view/" + ii["sha1"] + "\n"
                    loop_count += 1

        print_msg = print_msg + "\nMore information @ https://investigate.opendns.com/domain-view/name/"+input_value+'/view' + "\n"

    else:
        security_category = ""
        if resp_category_json[input_value].get("content_categories"):
            for i in resp_category_json[input_value]["content_categories"]:
                security_category +=  i + ", "
            print_msg = " " + input_value + " is categorized as " + security_category +"and not known to be either Good or Bad.\n * Security score is: " + secure_score + "\n * IP reputation is: " + rip_score + "\n * IP popularity is: " + popularity_score + "\n"
        else:
            print_msg = " " + input_value + " is Unclassified!\n * Security score is: " + secure_score + "\n * IP reputation is: " + rip_score + "\n * IP popularity is: " + popularity_score + "\n"

        ### ADD Associated Domains
        if type == 'ip':
            total_domains = int(resp_ip_domains_json.get("features").get("rr_count"))
            if total_domains > 0:
                print_msg = print_msg + " There are " + str(total_domains) + " associated with this ip address, some listed below:\n"
                loop_count = 1
                for iii in resp_ip_domains_json.get("rrs"):
                    if loop_count <= 5:
                        print_msg = print_msg + " * " + iii.get("rr") + " - Type (" + str(iii.get("type")) + ")" + "\n"
                        loop_count += 1
            else:
                print_msg = print_msg + " There is no domains associated with this IP address.\n"
        else:
            if resp_name_domains_json.get("rrs_tf"):
                record_resource = resp_name_domains_json.get("rrs_tf")[0]
                print_msg = print_msg + " Listed below are the Resource record for this domain:\n"
                loop_count = 1
                for iii in record_resource.get("rrs"):
                    if loop_count <= 5:
                        print_msg = print_msg + " * " + iii.get("rr") + " - Type (" + str(iii.get("type")) + ")" + "\n"
                        loop_count += 1
            else:
                print_msg = print_msg + " There is no Resource record for this domain.\n"
        ###

        if resp_samples_json.get("totalResults"):
            totalresults = int(resp_samples_json.get("totalResults"))
        else:
            totalresults = 0

        if totalresults > 0:
            print_msg = print_msg + " It has " + str(resp_samples_json["totalResults"]) + " malware samples, some listed below:" + "\n"
            loop_count = 1
            for ii in resp_samples_json["samples"]:
                if loop_count <= 5:
                    print_msg = print_msg + " * " + ii["sha1"] + " - Threat Score (" + str(ii["threatScore"]) + ")" + "\t - https://investigate.opendns.com/sample-view/" + ii["sha1"] + "\n"
                    loop_count += 1

        print_msg = print_msg + "\nMore information @ https://investigate.opendns.com/domain-view/name/"+input_value+'/view' + "\n"

    logger.info("ONDS DOMAIN OK!")
    print("ONDS DOMAIN OK!")

    return print_msg

######################################################
##########
########## Function CHECK HASH Investigate
##########
######################################################
def CHECK_HASH_ODNS (input_value):

    resp_hash = requests.get(odns_uri + odns_sample_info_url + input_value, headers=investigate_header)

    if resp_hash.status_code != 200:
        logger.info("HASH ONDS FAIL! -  " + str(resp_hash.status_code))
        return "Umbrella Error: API Call Status " + str(resp_hash.status_code)

    resp_hash_json = resp_hash.json()

#    print(json.dumps(resp_hash_json, indent=4, separators=(',', ': ')))

    if resp_hash_json.get("error"):
        return "NO information was found on this file!\n"

    odns_hash_threatscore = resp_hash_json.get("threatScore")
    odns_hash_type = resp_hash_json.get("magicType")

    print_msg = " " + str(input_value) + " was classified as " + str(odns_hash_type) + " with a threat score of " + str(odns_hash_threatscore) + "!\n\t These are the connections seen by ThreatGrid:\n"
    for i in resp_hash_json["connections"]['connections']:
        print_msg = print_msg + "\t\t" + i['name'] + "\n"
    print_msg = print_msg + " More information @ https://investigate.umbrella.com/sample-view/" + input_value + "\n"

    logger.info("ONDS HASH OK!")
    print("ONDS HASH OK!")

    return print_msg



######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
''''

if sys.argv[1] == '-ip':
    msg_to_print = CHECK_DOMAIN_ODNS(sys.argv[2],"ip")
    print (msg_to_print)
elif sys.argv[1] == '-domain':
    msg_to_print = CHECK_DOMAIN_ODNS(sys.argv[2],"domain")
    print(msg_to_print)
elif sys.argv[1] == '-hash':
    msg_to_print = CHECK_HASH_ODNS(sys.argv[2])
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''