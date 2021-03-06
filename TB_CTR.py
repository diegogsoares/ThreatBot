from TB_Logger import *
import credential
import requests
import json
import sys
from prettytable import PrettyTable


######################################################
##########
########## Autheticcate in CTR
##########
######################################################
def ctr_auth():
    url = 'https://visibility.amp.cisco.com/iroh/oauth2/token'
    headers = {'Content-Type':'application/x-www-form-urlencoded', 'Accept':'application/json'}
    payload = {'grant_type':'client_credentials'}
    response = requests.post(url, headers=headers, auth=(credential.ctr_client_id, credential.ctr_client_password), data=payload)
    token = response.json()
    header = {'Authorization':'Bearer {}'.format(token['access_token']), 'Content-Type':'application/json', 'Accept':'application/json'}
    
    return (header)

######################################################
##########
########## Find Observable Type
##########
######################################################
def ctr_search_type(observable,header):
    url = 'https://visibility.amp.cisco.com/iroh/iroh-inspect/inspect'
    inspect_payload = {'content':observable}
    inspect_payload = json.dumps(inspect_payload)
    response = requests.post(url, headers=header, data=inspect_payload)

    return (response.json())

######################################################
##########
########## Search CTR Info
##########
######################################################
def ctr_search(observable,header,action):

    if action == 'disposition':
        url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/deliberate/observables'
    elif action == 'links':
        url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/refer/observables'
    elif action == 'observables':
        url = 'https://visibility.amp.cisco.com/iroh/iroh-enrich/observe/observables'

    content = ctr_search_type(observable,header)
    payload = json.dumps(content)
    response = requests.post(url, headers=header, data=payload)

    return (response.json())

######################################################
##########
########## Create Nice Table to Print
##########
######################################################
def nice_print(response_json,header,artifact):

    result_text = ""
    disposition_msg = ctr_search(artifact,header,"disposition")
    links_msg = ctr_search(artifact,header,"links")

    for module in response_json['data']:
        result_text += "**"+str(module['module'])+"**  \n"
        for module_disposition in disposition_msg['data']:
            if module['module'] == module_disposition['module']:
                if 'verdicts' in module_disposition['data'] and module_disposition['data']['verdicts']['count'] > 0:
                    docs = module_disposition['data']['verdicts']['docs']
                    for doc in docs:
                        result_text += "Disposition: "+str(doc.get('disposition_name', 'N/A'))+" ("+str(doc.get('disposition', 'N/A'))+")"+"  \n"

        if (module.get('data').get('sightings')):
            result_text += "Number of Sightings: "+str(module.get('data').get('sightings').get("count", 'N/A'))+"  \n"
        
        if (module.get('data').get('judgements')):
            result_text += "*Number of Judgements: "+str(module.get('data').get('judgements').get("count", 'N/A'))+"  \n"

        for module_links in links_msg['data']:
            if module['module'] == module_links['module']:
                result_text += "Module URL: "+str(module_links['url'])+"\n\n"


    return (result_text)
######################################################
##########
########## Run CTR Search
##########
######################################################
def RUN_CTR (artifact):
    
    header = ctr_auth()
    msg = ctr_search(artifact,header,"observables")
    #print(json.dumps(msg, indent=4))   
    table = nice_print(msg,header,artifact)

    logger.info("CTR OK!")
    print("CTR OK!")

    return (table)

######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

if sys.argv[1]:
    table = RUN_CTR(sys.argv[1])
    print (table)

else:
    print("Provide Artifact!")

#'''