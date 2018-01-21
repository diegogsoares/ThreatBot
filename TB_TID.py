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

tid_url = 'https://10.87.31.155/api/'


######################################################
##########
########## GET Access Token
##########
######################################################
def GET_TID_TOKEN ():

    tid_token_url = tid_url + "fmc_platform/v1/auth/generatetoken"

    tid_token_header = {'Authorization': 'Basic ' + credential.tid_auth}
    resp_tid_token = requests.get(tid_token_url, headers=tid_token_header, verify=False)

#    if resp_tid_token.status_code != 200:
#        logger.info("TID FAIL! -  " + str(resp_tid_token.status_code))
#        return "FMC TID Error: API Call Status " + str(resp_tid_token.status_code)

    print (resp_tid_token.headers['X-auth-access-token'])

    return

######################################################
##########
########## Function Activity ThreatGrid
##########
######################################################
def ACTIVITY_QUERY_TG (input_value,input):


    return print_msg


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
#'''

if sys.argv[1] == '-ip':
    msg_to_print = CHECK_QUERY_TG(sys.argv[2],"ip")
    print (msg_to_print)
elif sys.argv[1] == '-token':
    msg_to_print = GET_TID_TOKEN()
    print (msg_to_print)
elif sys.argv[1] == '-hash':
    msg_to_print = CHECK_QUERY_TG(sys.argv[2],"hash")
    print(msg_to_print)
elif sys.argv[1] == '-domain':
    msg_to_print = CHECK_QUERY_TG(sys.argv[2],"domain")
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''