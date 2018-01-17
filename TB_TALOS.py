from TB_Logger import *
import requests
import dns.resolver
import sys

requests.packages.urllib3.disable_warnings()

from bs4 import BeautifulSoup
from robobrowser import RoboBrowser

######################################################
##########
########## Check Talos Block List
##########
######################################################
def TALOS_BLOCK_LIST(input_value,type):

    input_value_ip = input_value
    dns_ip = True
    if type == "domain":
        try:
            my_resolver = dns.resolver.Resolver()
#            my_resolver.nameservers = ['8.8.8.8']
            my_resolver.timeout = 3
            answers = my_resolver.query(input_value, "A")
            input_value = str(answers[0])
        except:
            dns_ip = False

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
        print_msg = "Talos Block list has %s entries and IP: %s WAS found!" % (talos_count,input_value)
    else:
        print_msg = "Talos Block list has %s entries and IP: %s was NOT found!" % (talos_count,input_value)

    datalist.close()

    logger.info("TALOS BL OK!")
    print("TALOS BL OK!")

    ############

    s = requests.Session()
    browser = RoboBrowser(session=s)
    browser = RoboBrowser(parser='html.parser')

    url_ip = "https://amptools.cisco.com/network.php?query="+input_value_ip

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
                print_msg = print_msg + "\nTalos Category:" + str(cleanTalosscore)
                print_msg = print_msg + "\nTalos " + statusTalos
            else:
                logger.info("TALOS AMPTOOLBOX OK!")
                print("TALOS AMPTOOLBOX OK!")
                print_msg = print_msg + "\nTalos Category: Unknown"
                return (print_msg)

    logger.info("TALOS AMPTOOLBOX OK!")
    print("TALOS AMPTOOLBOX OK!")

    return print_msg


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

if sys.argv[1] == '-ip':
    msg_to_print = TALOS_BLOCK_LIST(sys.argv[2],"ip")
    print (msg_to_print)
elif sys.argv[1] == '-domain':
    msg_to_print = TALOS_BLOCK_LIST(sys.argv[2],"domain")
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''
