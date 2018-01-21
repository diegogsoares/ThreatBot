#from TB_Logger import *
import requests
import sys


######################################################
##########
########## Variables TG APIs
##########
######################################################
import credential

tid_url = 'https://172.16.20.20/api/'


######################################################
##########
########## GET Access Token
##########
######################################################
def GET_TID_TOKEN ():

    tid_token_url = tid_url + "fmc_platform/v1/auth/generatetoken"

    tid_token_header = {'Authorization': 'Basic ' + credential.tid_auth}
    resp_tid_token = requests.post(tid_token_url, headers=tid_token_header, verify=False)

#    if resp_tid_token.status_code != 200:
#        logger.info("TID FAIL! -  " + str(resp_tid_token.status_code))
#        return "FMC TID Error: API Call Status " + str(resp_tid_token.status_code)

    access_token = resp_tid_token.headers['X-auth-access-token']

    return access_token

######################################################
##########
########## Function Activity ThreatGrid
##########
######################################################
def GET_TID_IOCS ():

    tid_iocs_url = tid_url + "fmc_tid/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/tid/indicator"

    tid_ioc_header = {"Accept": "application/json", "Content-Type": "application/json", 'X-auth-access-token': GET_TID_TOKEN ()}
    resp_tid_iocs = requests.get(tid_iocs_url, headers=tid_ioc_header, verify=False)

    return resp_tid_iocs


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
    msg_to_print = GET_TID_IOCS()
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