from TB_Logger import *
import requests
import sys

requests.packages.urllib3.disable_warnings()

from bs4 import BeautifulSoup
from robobrowser import RoboBrowser

######################################################
##########
########## Check Talos Block List
##########
######################################################
def TALOS_BLOCK_LIST(input_value):
    talos_bl = False
    datalist = open("ip-filter.blf", "r")
    iplist = datalist.readline()
    talos_count = 0

    while iplist:
        if iplist.strip() == input_value:
            talos_bl = True
        iplist = datalist.readline()
        talos_count += 1

    if talos_bl == True:
        print_msg = "Block list has %s entries and IP: %s WAS found!" % (talos_count,input_value)
    else:
        print_msg = "Block list has %s entries and IP: %s was NOT found!" % (talos_count,input_value)

    datalist.close()

    logger.info("TALOS BL OK!")
    print("TALOS BL OK!")

    return print_msg

######################################################
##########
########## Check Talos on AMP ToolBox
##########
######################################################
def amptoolbox(input_value,type):

    s = requests.Session()
    browser = RoboBrowser(session=s)
    browser = RoboBrowser(parser='html.parser')

    url_file = "https://amptools.cisco.com/results.php?tg_key=&hashes="+input_value
    url_ip = "https://amptools.cisco.com/network.php?query="+input_value

    if type == 'hash256':
        browser.open(url_file)

        page = BeautifulSoup(str(browser.parsed), "lxml")
        table = page.find("table", {"class": "customvt"})

        rows = cells = list()
        for rows in table.findAll("tr"):
            row = BeautifulSoup(str(rows), "lxml").text
            if "ThreatGrid" in row:
                cellsTG = rows.findAll("td")
                scoreTG = cellsTG[1].findAll("p")
                cleanTGscore = BeautifulSoup(str(scoreTG), "lxml").text
                print("TG Threat Score:" + str(cleanTGscore))
            elif "Talos Intel" in row:
                cellsTalos = rows.findAll("td")
                scoreTalos = cellsTalos[1].findAll("p")
                cleanTalosscore = BeautifulSoup(str(scoreTalos), "lxml").text
                print("Talos Threat Score:" + str(cleanTalosscore))
            elif "AMP Cloud" in row:
                cellsAMP = rows.findAll("td")
                scoreAMP = cellsAMP[1].findAll("p")
                cleanAMPscore = BeautifulSoup(str(scoreAMP), "lxml").text
                print("AMP Disposition:" + str(cleanAMPscore))

        return ()

    elif type == 'domain' or type == 'ip':
        browser.open(url_ip)

        page = BeautifulSoup(str(browser.parsed), "lxml")
        table = page.find("table", {"class": "customvt"})

        rows = cells = list()
        for rows in table.findAll("tr"):
            row = BeautifulSoup(str(rows), "lxml").text
            if "Talos" in row:
                cellsTalos = rows.findAll("td")
                scoreTalos = cellsTalos[1].findAll("p")
                for line in cellsTalos[1]:
                    if "Status:" in line:
                        statusTalos = line.strip()
                cleanTalosscore = BeautifulSoup(str(scoreTalos), "lxml").text
                if cleanTalosscore != '[]':
                    print_msg = "Talos Category:" + str(cleanTalosscore)
                    print_msg = print_msg + "\nTalos " + statusTalos
                    return(print_msg)
                else:
                    return ("Unknown to Talos!")

    return ("No results from Talos.")


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

if sys.argv[1] == '-ip':
    msg_to_print = TALOS_BLOCK_LIST(sys.argv[2])
    print (msg_to_print)
    msg_to_print1 = amptoolbox(sys.argv[2],"ip")
    print (msg_to_print1)
elif sys.argv[1] == '-domain':
    msg_to_print = amptoolbox(sys.argv[2],"domain")
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''
