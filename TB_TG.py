from TB_Logger import *
import requests
import sys

requests.packages.urllib3.disable_warnings()

######################################################
##########
########## Variables TG APIs
##########
######################################################
import credential

tg_url = 'https://panacea.threatgrid.com/api/v2/'


######################################################
##########
########## Function CHECK IP ThreatGrid
##########
######################################################
def CHECK_INTEL_TG (input_value,input):

    parameters_ip_tg='api_key='+credential.tg_apikey+'&q='+input_value+'&limit=50'
    resp_ip_tg = requests.get(tg_url+'search/submissions?', params=parameters_ip_tg, verify=False)

    if resp_ip_tg.status_code != 200:
        logger.info("TG FAIL! -  " + str(resp_ip_tg.status_code))
        return "ThreatGrig Error: API Call Status " + str(resp_ip_tg.status_code)

    resp_ip_tg_json = resp_ip_tg.json()
    samples_tg_count = str(resp_ip_tg_json['data']['current_item_count'])

    ################
    ### ADD TG INFORMATION
    ################
    if input == 'ip':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/ips/" + input_value + "\n"
    elif input == "domain":
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/domains/" + input_value + "\n"
    elif input =='hash':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/artifacts/" + input_value + "\n"

    ################
    ### ADD TG SAMPLES
    ################
    if resp_ip_tg_json['data']['current_item_count'] == 0:
        print_msg = "NO Samples were found on " + input_value + "\n"
    else:
        print_msg = "We found " + samples_tg_count + " Malware Samples!\n\tThis is/are some sample(s) found:\n"

    loop_count =1

    for i in resp_ip_tg_json['data']['items']:
        #i_json = i.json()
        if 'analysis' in i['item']:
            if loop_count <= 5:
                print_msg = print_msg + " * " + str(i['item']['sha256']) + " (" + str(i['item']['analysis']['threat_score']) + ") - https://panacea.threatgrid.com/mask/#/samples/" + str(i['item']['sample']) + "\n"
                loop_count += 1

    ################
    ### ADD TG LINK
    ################
    if input == 'ip':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/ips/" + input_value + "\n"
    elif input == "domain":
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/domains/" + input_value + "\n"
    elif input =='hash':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/artifacts/" + input_value + "\n"

    logger.info("TG OK!")
    print("TG OK!")


    return print_msg

######################################################
##########
########## Function Activity ThreatGrid
##########
######################################################
def ACTIVITY_QUERY_TG (input_value,input):

    parameters_ip_tg='api_key='+credential.tg_apikey+'&q='+input_value+'&org_only=true&limit=50'
    resp_ip_tg = requests.get(tg_url+'search/submissions?', params=parameters_ip_tg)

    if resp_ip_tg.status_code != 200:
        logger.info("TG FAIL! -  " + str(resp_ip_tg.status_code))
        return "ThreatGrig Error: API Call Status " + str(resp_ip_tg.status_code)

    resp_ip_tg_json = resp_ip_tg.json()

#    print(json.dumps(resp_ip_tg_json, indent=4, separators=(',', ': ')))

    samples_tg_count = str(resp_ip_tg_json['data']['current_item_count'])

    if resp_ip_tg_json['data']['current_item_count'] == 0:
        print_msg = "NO information was found on " + input_value + "\n"
    else:
        print_msg = "We found " + samples_tg_count + " Malware Samples!\n\tThis is/are some sample(s) found:\n"

    loop_count =1

    for i in resp_ip_tg_json['data']['items']:
        #i_json = i.json()
        if 'analysis' in i['item']:
            if loop_count <= 5:
                print_msg = print_msg + "\t" + str(i['item']['sha256']) + " (" + str(i['item']['analysis']['threat_score']) + ") - https://panacea.threatgrid.com/mask/#/samples/" + str(i['item']['sample']) + "\n"
                loop_count += 1

    if input == 'ip':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/ips/" + input_value + "\n"
    elif input == "domain":
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/domains/" + input_value + "\n"
    elif input =='hash':
        print_msg = print_msg + " More information @ https://panacea.threatgrid.com/mask/#/search/samples?term=freeform&q=" + input_value + "\n"

    logger.info("TG OK!")
    print("TG OK!")


    return print_msg


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
#'''

if sys.argv[1] == '-ip':
    msg_to_print = CHECK_INTEL_TG(sys.argv[2],"ip")
    print (msg_to_print)
elif sys.argv[1] == '-hash':
    msg_to_print = CHECK_INTEL_TG(sys.argv[2],"hash")
    print(msg_to_print)
elif sys.argv[1] == '-domain':
    msg_to_print = CHECK_INTEL_TG(sys.argv[2],"domain")
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''