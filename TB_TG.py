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

    print_msg = good_flags = bad_flags = ""
    good_flag_count = bad_flag_count =0


    parameters_tg='api_key='+credential.tg_apikey+'&limit=50&q='+input_value
    resp_tg = requests.get(tg_url+'search/submissions?', params=parameters_tg, verify=False)

    if resp_tg.status_code != 200:
        logger.info("TG FAIL! -  " + str(resp_tg.status_code))
        return "ThreatGrig Error: API Call Status " + str(resp_tg.status_code)

    resp_tg_json = resp_tg.json()
    samples_tg_count = str(resp_tg_json['data']['total'])

    ################
    ### ADD TG INFORMATION
    ################
    if input == 'ip':
        tg_ip_url = "https://panacea.threatgrid.com/api/v2/ips/"+input_value+'?'
        parameters_ip_tg = 'api_key='+credential.tg_apikey+'&limit=50'
        resp_ip_tg = requests.get(tg_ip_url, params=parameters_ip_tg, verify=False)

        if resp_ip_tg.status_code != 200:
            logger.info("TG FAIL! -  " + str(resp_ip_tg.status_code))
            return "ThreatGrig Error: API Call Status " + str(resp_ip_tg.status_code)

        resp_ip_tg_json = resp_ip_tg.json()

        for flags in resp_ip_tg_json.get('data').get('flags'):
            if str(flags.get('flag')) == str(1):
                good_flag_count +=1
                good_flags = good_flags +", "+ flags.get('reason')
            if str(flags.get('flag')) == str(-1):
                bad_flag_count += 1
                bad_flags = bad_flags + ", " + flags.get('reason')

        if good_flag_count != 0:
            print_msg = print_msg + "This IP has been flagged " + str(good_flag_count) + " times as a GOOD IP with the following tags"+str(good_flags)+"\n"
        if bad_flag_count != 0:
            print_msg = print_msg + "This IP has been flagged " + str(bad_flag_count) + " times as a BAD IP with the following tags" +str(bad_flags)+ "\n"

        ### FUTURE FEATURE - ADD QUERY for related domains
        # https://panacea.threatgrid.com/api/v2/search/domains?api_key=XXXXXXXXXXXX&after=YYYY-MM-DD&term=ip&query=[ip]

    elif input == "domain":
        tg_domain_url = "https://panacea.threatgrid.com/api/v2/domains/"+input_value+'?'
        parameters_domain_tg = 'api_key='+credential.tg_apikey+'&limit=50'
        resp_domain_tg = requests.get(tg_domain_url, params=parameters_domain_tg, verify=False)

        if resp_domain_tg.status_code != 200:
            logger.info("TG FAIL! -  " + str(resp_domain_tg.status_code))
            return "ThreatGrig Error: API Call Status " + str(resp_domain_tg.status_code)

        resp_domain_tg_json = resp_domain_tg.json()

        for flags in resp_domain_tg_json.get('data').get('flags'):
            if str(flags.get('flag')) == str(1):
                good_flag_count +=1
                good_flags = good_flags +", "+ flags.get('reason')
            if str(flags.get('flag')) == str(-1):
                bad_flag_count += 1
                bad_flags = bad_flags + ", " + flags.get('reason')

        if good_flag_count != 0:
            print_msg = print_msg + "This Domain has been flagged " + str(good_flag_count) + " times as a GOOD domain with the following tags"+str(good_flags)+"\n"
        if bad_flag_count != 0:
            print_msg = print_msg + "This Domain has been flagged " + str(bad_flag_count) + " times as a BAD domain with the following tags" +str(bad_flags)+ "\n"

        ### FUTURE FEATURE - ADD QUERY for related IPs
        #https://panacea.threatgrid.com/api/v2/search/ips?api_key=XXXXXXXXXXXX&after=YYYY-MM-DD&term=domain&query=[domain]


    elif input =='hash':
        tg_hash_url = "https://panacea.threatgrid.com/api/v2/artifacts/"+input_value+'?'
        parameters_hash_tg = 'api_key='+credential.tg_apikey+'&limit=50'
        resp_hash_tg = requests.get(tg_hash_url, params=parameters_hash_tg, verify=False)

        if resp_hash_tg.status_code != 200:
            logger.info("TG FAIL! -  " + str(resp_hash_tg.status_code))
            return "ThreatGrig Error: API Call Status " + str(resp_hash_tg.status_code)

        resp_hash_tg_json = resp_hash_tg.json()

        for flags in resp_hash_tg_json.get('data').get('flags'):
            if str(flags.get('flag')) == str(1):
                good_flag_count +=1
                good_flags = good_flags +", "+ flags.get('reason')
            if str(flags.get('flag')) == str(-1):
                bad_flag_count += 1
                bad_flags = bad_flags + ", " + flags.get('reason')

        if good_flag_count != 0:
            print_msg = print_msg + "This HASH has been flagged " + str(good_flag_count) + " times as a GOOD hash with the following tags"+str(good_flags)+"\n"
        if bad_flag_count != 0:
            print_msg = print_msg + "This HASH has been flagged " + str(bad_flag_count) + " times as a BAD hash with the following tags" +str(bad_flags)+ "\n"

        hash_type = resp_hash_tg_json.get('data').get('type')
        print_msg = print_msg + "This HASH has been identified as " + str(hash_type) + "\n"

        ### FUTURE FEATURE - ADD QUERY for related IPs
        #https://panacea.threatgrid.com/api/v2/search/ips?api_key=XXXXXXXXXXXX&after=YYYY-MM-DD&term=artifact&query=[hash]
        ### FUTURE FEATURE - ADD QUERY for related domains
        # https://panacea.threatgrid.com/api/v2/search/domains?api_key=XXXXXXXXXXXX&after=YYYY-MM-DD&term=sha256&query=[hash]



    ################
    ### ADD TG SAMPLES
    ################
    if resp_tg_json['data']['total'] == 0:
        print_msg = print_msg + "\nNO Samples were found on " + input_value + "\n"
    else:
        print_msg = print_msg + "\nWe found " + samples_tg_count + " Malware Samples!\n\tThis is/are some sample(s) found:\n"

    loop_count =1

    for i in resp_tg_json['data']['items']:
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
'''

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