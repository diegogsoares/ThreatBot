import requests
import sys

requests.packages.urllib3.disable_warnings()

######################################################
##########
########## Variables AMP TOOLBOX API
##########
######################################################
import credential

toolbox_url = 'https://amptools.cisco.com/api.php?api_key='+credential.toolbox_api_key+'&talos=1&amp=1&hash='

######################################################
##########
########## CHECK AMP TOOLBOX Function
##########
######################################################
def CHECK_AMPTOOLBOX (input_value):

    resp_toolbox = requests.get(toolbox_url+input_value, verify=False)

    if resp_toolbox.status_code != 200:
        logger.info("AMP TOOLBOX FAIL! -  " + str(resp_toolbox.status_code))
        return "AMP Error: API Call Status " + str(resp_toolbox.status_code)

    resp_toolbox_json = resp_toolbox.json()

    toolbox_talos_score = resp_toolbox_json.get("talos_score")
    toolbox_disposition = resp_toolbox_json.get("disposition")

    print_msg = "Talos threat score for this file is: " + str(toolbox_talos_score) + "\nFile disposition is " + str(toolbox_disposition)

    if resp_toolbox_json.get("threat_name") != None:
        print_msg = print_msg + " and threat name is " + str(resp_toolbox_json.get("threat_name"))

    print_msg = print_msg + "\nMore about file details @ https://console.amp.cisco.com/file/" + input_value + "/profile/details\n"
    
    return print_msg



######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

msg_to_print = CHECK_AMPTOOLBOX(sys.argv[1])
print (msg_to_print)

#'''