#from TB_Logger import *
import requests
import json
import datetime
import sys

requests.packages.urllib3.disable_warnings()

######################################################
##########
########## Variables TG APIs
##########
######################################################
import credential

tid_url = 'https://10.87.31.155/api/'
#tid_url = 'https://172.16.20.20/api/'

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
########## Function List IOCs FMC TID
##########
######################################################
def GET_TID_IOCS (ioc_id):

    tid_iocs_url = tid_url + "fmc_tid/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/tid/indicator"
    tid_ioc_header = {"Accept": "application/json", "Content-Type": "application/json", 'X-auth-access-token': GET_TID_TOKEN ()}
    count = 0

    if ioc_id != '':
        tid_iocs_url = tid_iocs_url + "/" + ioc_id
        resp_tid_iocs = requests.get(tid_iocs_url, headers=tid_ioc_header, verify=False)
        tid_ioc_json = resp_tid_iocs.json()
        return (tid_ioc_json)

    else:
        tid_iocs_url = tid_iocs_url + "?limit=40"
        resp_tid_iocs = requests.get(tid_iocs_url, headers=tid_ioc_header, verify=False)
        tid_ioc_json = resp_tid_iocs.json()
        pages_num = tid_ioc_json.get('paging').get('pages')
        next_page = tid_ioc_json.get('paging').get('next')
        offset = tid_ioc_json.get('paging').get('offset')
        print (pages_num)
        while count <= pages_num:
            count += 1
            try:
                print(next_page[0])
                print(offset)
                resp_tid_iocs = requests.get(next_page[0], headers=tid_ioc_header, verify=False)
                tid_ioc_json = resp_tid_iocs.json()
                next_page = tid_ioc_json.get('paging').get('next')
                offset = tid_ioc_json.get('paging').get('offset')
            except:
                print('')

            print(count)

    return


######################################################
##########
########## Function List Observable FMC TID
##########
######################################################
def GET_TID_observable (observable_id):

    tid_observable_url = tid_url + "fmc_tid/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/tid/observable"
    tid_observable_header = {"Accept": "application/json", "Content-Type": "application/json", 'X-auth-access-token': GET_TID_TOKEN ()}
    count = 0

    if observable_id != '':
        tid_observable_url = tid_observable_url + "/" + observable_id
        resp_tid_observable = requests.get(tid_observable_url, headers=tid_observable_header, verify=False)
        tid_observable_json = resp_tid_observable.json()
        return (tid_observable_json)

    else:
        tid_observable_url = tid_observable_url + "?limit=40"
        resp_tid_observable = requests.get(tid_observable_url, headers=tid_observable_header, verify=False)
        tid_observable_json = resp_tid_observable.json()
        pages_num = tid_observable_json.get('paging').get('pages')
        next_page = tid_observable_json.get('paging').get('next')
        offset = tid_observable_json.get('paging').get('offset')
        print (pages_num)
        while count <= pages_num:
            count += 1
            try:
                print (next_page[0])
            except:
                print ('')
            print (offset)
            print (count)
            resp_tid_observable = requests.get(next_page[0], headers=tid_observable_header, verify=False)
            tid_observable_json = resp_tid_observable.json()
            next_page = tid_observable_json.get('paging').get('next')
            offset = tid_observable_json.get('paging').get('offset')

    return


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
#'''

if sys.argv[1] == '-observable':
    date_begin = datetime.datetime.time(datetime.datetime.now())
    try:
        ioc_id = sys.argv[2]
        msg_to_print = GET_TID_observable(sys.argv[2])
        print(json.dumps(msg_to_print, indent=4, separators=(',', ': ')))
    except:
        msg_to_print = GET_TID_observable('')
        print("Observables Updated!")
        date_end = datetime.datetime.time(datetime.datetime.now())
        print(date_end - date_begin)
elif sys.argv[1] == '-ioc':
    date_begin = datetime.datetime.time(datetime.datetime.now())
    try:
        ioc_id = sys.argv[2]
        msg_to_print = GET_TID_IOCS(sys.argv[2])
        print(json.dumps(msg_to_print, indent=4, separators=(',', ': ')))
    except:
        msg_to_print = GET_TID_IOCS('')
        date_end = datetime.datetime.time(datetime.datetime.now())
        print("IOCs Updated!")
        date_end = datetime.datetime.time(datetime.datetime.now())
        print(date_end - date_begin)
elif sys.argv[1] == '-hash':
    msg_to_print = CHECK_QUERY_TG(sys.argv[2],"hash")
    print(msg_to_print)
elif sys.argv[1] == '-domain':
    msg_to_print = CHECK_QUERY_TG(sys.argv[2],"domain")
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''