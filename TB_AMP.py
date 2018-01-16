from TB_Logger import *
import requests
import sys

######################################################
##########
########## Variables AMP APIs
##########
######################################################
import credential

### API URLs - AMP
amp_header = {'Authorization': 'Basic ' + credential.amp_auth_token,'Content-Type': 'application/json', 'Accept': 'application/json'}
amp_url = 'https://api.amp.cisco.com'
amp_url_pc = 'https://api.amp.cisco.com/v1/computers/activity?q='
amp_url_hash = 'https://api.amp.cisco.com/v1/events?application_sha256='

######################################################
##########
########## Function CHECK PC AMP
##########
######################################################
def CHECK_AMP (input_value,type):

    resp_amp = requests.get(amp_url_pc+input_value, headers=amp_header)

    if resp_amp.status_code != 200:
        logger.info("AMP FAIL! -  " + str(resp_amp.status_code))
        return "AMP Error: API Call Status " + str(resp_amp.status_code)

    resp_amp_json = resp_amp.json()

#    print(json.dumps(resp_amp_json, indent=4, separators=(',', ': ')))

    if type == 'hash256':
        resp_amp_hash = requests.get(amp_url_hash + input_value, headers=amp_header)
        if resp_amp_hash.status_code != 200:
            logger.info("HASH AMP FAIL! -  " + str(resp_amp_hash.status_code))
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
        print_msg = "File disposition is " + hash_disposition +" and " + str(resp_amp_json['metadata']['results']['total']) + " Connectors that saw this activity!\n\tThis are/were the connector(s):\n"
    else:
        if resp_amp_json['metadata']['results']['total'] != 0:
            print_msg = "We found " + str(resp_amp_json['metadata']['results']['total']) + " Connectors that saw this activity!\n\tThis are/were the connector(s):\n"
        else:
            print_msg = "We did not find any activity!\n"

    loop_count = 1
    for i in resp_amp_json["data"]:
        if loop_count <=5:
            print_msg = print_msg + '\t\tConnector GUID: ' + str(i['connector_guid']) + " - " +  str(i['links']['computer']) + "\n"
            loop_count += 1

    print_msg = print_msg + "More activity information @ https://console.amp.cisco.com/search?query=" + input_value

    if type == 'hash256':
        print_msg = print_msg + "\nMore about file details @ https://console.amp.cisco.com/file/" + input_value + "/profile/details\n"

    logger.info("AMP OK!")
    print("AMP OK!")


    return print_msg


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

if sys.argv[1] == '-hash':
    msg_to_print = CHECK_AMP(sys.argv[2],"hash256")
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''