import requests
import credential
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
def nice_print(response_json):

    result = []
    disposition_msg = ctr_search(sys.argv[1],header,"disposition")
    links_msg = ctr_search(sys.argv[1],header,"links")

    for module in response_json['data']:
        item = {}
        item['module_name'] = module['module']
        for module_disposition in disposition_msg['data']:
            if item['module_name'] == module_disposition['module']:
                if 'verdicts' in module_disposition['data'] and module_disposition['data']['verdicts']['count'] > 0:
                    docs = module_disposition['data']['verdicts']['docs']
                    for doc in docs:
                        item['disposition'] = doc.get('disposition', 'None')
                        item['disposition_name'] = doc.get('disposition_name', 'None')

        for module_links in links_msg['data']:
            if item['module_name'] == module_links['module']:
                item['url'] = module_links['url']

        if (module.get('data').get('sightings')):
            item['sightings_count'] = module.get('data').get('sightings').get("count")
        
        if (module.get('data').get('judgements')):
            item['judgements_count'] = module.get('data').get('judgements').get("count")

        result.append(item)

    table = PrettyTable()
    table.field_names = ['Module Name', 'Disposition', 'Disposition Name', 'Sightings Count', 'Judgements Count']
    table.add_row([ '','','','',''])

    for item in result:
        table.add_row([item.get('module_name'),item.get('disposition'),item.get('disposition_name'),item.get('sightings_count'),item.get('judgements_count')])
        table.add_row([ '','','','',''])
        
    #print(json.dumps(result, indent=4))
    print (table)

    return
######################################################
##########
########## Run CTR Search
##########
######################################################
def run_ctr (artifact):
    header = ctr_auth()
    msg = ctr_search(artifact,header,"observables")
    #print(json.dumps(msg, indent=4))   
    nice_print(msg)

    return 

######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
#'''

if sys.argv[1]:
    run_ctr(sys.argv[1])

else:
    print("Provide Artifact!")

#'''