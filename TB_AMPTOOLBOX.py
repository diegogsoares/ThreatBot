import requests
import sys
from bs4 import BeautifulSoup
from robobrowser import RoboBrowser
from TB_Logger import *

requests.packages.urllib3.disable_warnings()

######################################################
##########
########## Variables AMP TOOLBOX API
##########
######################################################
import credential

toolbox_url = 'https://amptools.cisco.com/api.php?api_key='+credential.toolbox_api_key+'&talos=1&amp=1&hash='
threat_date = ''

######################################################
##########
########## CHECK AMP TOOLBOX API Function
##########
######################################################
def CHECK_AMPTOOLBOX (input_value):

    resp_toolbox = requests.get(toolbox_url+input_value, verify=False)

    if resp_toolbox.status_code != 200:
        logger.info("AMP TOOLBOX API FAIL! -  " + str(resp_toolbox.status_code))
        return "AMP Error: API Call Status " + str(resp_toolbox.status_code)

    resp_toolbox_json = resp_toolbox.json()

    toolbox_talos_score = resp_toolbox_json.get("talos_score")
    toolbox_disposition = resp_toolbox_json.get("disposition")

    print_msg = "File disposition is " + str(toolbox_disposition)

    if resp_toolbox_json.get("threat_name") != None:
        print_msg = print_msg + " and threat name is " + str(resp_toolbox_json.get("threat_name"))

    print_msg = print_msg + "\nTalos threat score for this file is: " + str(toolbox_talos_score)

    #threat_date = CHECK_AMPTOOLBOX_PAGE(input_value)

    if threat_date != "Unknown":
        print_msg = print_msg + "\nThis hash was assigned as Malicious on:" + str(threat_date)

    print_msg = print_msg + "\nMore about file details @ https://www.talosintelligence.com/talos_file_reputation?s=" + input_value

    logger.info("TALOS AMPTOOLBOX API OK!")
    print("TALOS AMPTOOLBOX API OK!")

    return print_msg


######################################################
##########
########## CHECK AMP TOOLBOX PAGE Function
##########
######################################################
def CHECK_AMPTOOLBOX_PAGE (input_value):

    input_value_original = input_value
    threat_date = "Unknown"

    ############

    s = requests.Session()
    browser = RoboBrowser(session=s)
    browser = RoboBrowser(parser='html.parser')

    url_hash = "https://amptools.cisco.com/results.php?hashes="+input_value_original

    browser.open(url_hash)

    page = BeautifulSoup(str(browser.parsed), "lxml")

    print(page)

    table = page.find("table", {"class": "customvt2"})

    rows = cells = list()
    for rows in table.findAll("tr"):
        row = BeautifulSoup(str(rows), "lxml").text
        if "AMP Cloud" in row:
            cellsTalos = rows.findAll("td")
            for line in cellsTalos[1]:
                if "Assigned Malicious:" in line:
                    threat_line = line.strip()
                    threat_line = threat_line.split(":")
                    threat_date = threat_line[1]+":"+threat_line[2]+":"+threat_line[3]

    logger.info("TALOS AMPTOOLBOX PAGE OK!")
    print("TALOS AMPTOOLBOX PAGE OK!")

    return threat_date



######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

msg_to_print = CHECK_AMPTOOLBOX(sys.argv[1])
print (msg_to_print)


#'''