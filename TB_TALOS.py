from TB_Logger import *
import requests
import dns.resolver
import sys
import validators

requests.packages.urllib3.disable_warnings()

from bs4 import BeautifulSoup
from robobrowser import RoboBrowser

######################################################
##########
########## Check Talos Block List
##########
######################################################
def TALOS_BLOCK_LIST(input_value,type):

    BCcategory = '[]'
    cleanBCscore = '[]'
    input_value_original = input_value
    input_ip = input_value
    print_msg = ""

    ############

    s = requests.Session()
    browser = RoboBrowser(session=s)
    browser = RoboBrowser(parser='html.parser')

    print_msg_BC = ""

    url_ip = "https://amptools.cisco.com/network.php?query="+input_value_original

    browser.open(url_ip)

    page = BeautifulSoup(str(browser.parsed), "lxml")
    table = page.find("table", {"class": "customvt"})

    rows = cells = list()
    for rows in table.findAll("tr"):
        row = BeautifulSoup(str(rows), "lxml").text
        if "Talos" in row:
            cellsTalos = rows.findAll("td")
            scoreTalos = cellsTalos[1].findAll("p")
            cleanTalosscore = BeautifulSoup(str(scoreTalos), "lxml").text
            statusTalos = None
            for line in cellsTalos[1]:
                if "Status:" in line:
                    statusTalos = line.strip()
            if cleanTalosscore != '[]':
                print_msg = print_msg + "Talos Category for "+str(input_value_original)+": " + str(cleanTalosscore)
                status_list = statusTalos.split(":")
                print_msg = print_msg + "\nTalos BLOCK Status for "+str(input_value_original)+":" + status_list[1]
            else:
                print_msg = print_msg + "Talos Category: Unknown"
        elif "BrightCloud" in row:
            cellsBC = rows.findAll("td")
            scoreBC = cellsBC[1].findAll("p")
            cleanBCscore = BeautifulSoup(str(scoreBC), "lxml").text
            for line in cellsBC[1]:
                if "Reputation:" in line:
                    BCreputation = line.strip()
                elif "Category:" in line:
                    BCcategory = line.strip()

            if BCcategory != '[]' and cleanBCscore != '[]':
                print_msg_BC = print_msg_BC + "BrightCloud " + BCreputation + " " + str(cleanBCscore)
                print_msg_BC = print_msg_BC + "\nBrightCloud " + BCcategory
            elif BCcategory != '[]' and cleanBCscore == '[]':
                print_msg_BC = print_msg_BC + "BrightCloud " + BCreputation
                print_msg_BC = print_msg_BC + "\nBrightCloud " + BCcategory
            else:
                print_msg_BC = print_msg_BC + "BrightCloud Category: Unknown"


    logger.info("TALOS AMPTOOLBOX OK!")
    print("TALOS AMPTOOLBOX OK!")

    ##############################

    if type == "domain":
        answers_cname = "sinkhole.esl.cisco.com."
        try:
            my_resolver = dns.resolver.Resolver()
#            my_resolver.nameservers = ['8.8.8.8']
            my_resolver.timeout = 3
            answers = my_resolver.query(input_value, "A")
            answers_cname = my_resolver.query(input_value, "CNAME")
            input_ip = str(answers[0])
        except:
            logger.info("DNS Query Failed!")
            print("DNS Query Failed!")

        if str(answers_cname[0]) == "sinkhole.esl.cisco.com.":
            resp_http_dns = requests.get("https://dns.google.com/resolve?type=A&name="+str(input_value), verify=False)

            if resp_http_dns.status_code != 200:
                logger.info("HTTP DNS FAIL! -  " + str(resp_http_dns.status_code))
                return "HTTP DNS FAIL: API Call Status " + str(resp_http_dns.status_code)

            resp_http_dns_json = resp_http_dns.json()
            resp_ip = resp_http_dns_json.get("Answer")

            if resp_ip:
                for i in resp_ip:
                    if validators.ipv4(i.get("data")):
                        input_ip = i.get("data")
            else:
                input_ip = "0.0.0.0"


    talos_bl = False
    datalist = open("ip-filter.blf", "r")
    iplist = datalist.readline()
    talos_count = 0

    while iplist:
        if iplist.strip() == input_ip:
            talos_bl = True
        iplist = datalist.readline()
        talos_count += 1

    if talos_bl == True:
        print_msg = print_msg + "\nTalos IP Block list has %s entries and IP: %s WAS found!" % (talos_count,input_ip)
        print_msg = print_msg + "\nMore information @ https://www.talosintelligence.com/reputation_center/lookup?search=" + input_value_original
    else:
        if input_ip != "0.0.0.0":
            print_msg = print_msg + "\nTalos IP Block list has %s entries and IP: %s was NOT found!" % (talos_count,input_ip)
        else:
            print_msg = print_msg + "\nIP for this domain could not be resolved."
        print_msg = print_msg + "\nMore information @ https://www.talosintelligence.com/reputation_center/lookup?search=" + input_value_original

    datalist.close()

    logger.info("TALOS BL OK!")
    print("TALOS BL OK!")


    ##############################

    if type == "ip":
        return (print_msg, "ip")
    elif type == "domain":
        return (print_msg, print_msg_BC)
    else:
        return


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

if sys.argv[1] == '-ip':
    msg_to_print, msg_to_print2 = TALOS_BLOCK_LIST(sys.argv[2],"ip")
    print (msg_to_print)
    print (msg_to_print2)
elif sys.argv[1] == '-domain':
    msg_to_print, msg_to_print2 = TALOS_BLOCK_LIST(sys.argv[2],"domain")
    print(msg_to_print)
    print (msg_to_print2)
else:
    print("Invalid Operation!")

#'''
