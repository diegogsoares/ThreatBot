import json
import requests
import validators
from itty import *
import urllib2


requests.packages.urllib3.disable_warnings()

###
### Next feeds:
### mxtoolbox.com/SuperTool.aspx#
### Stealthwatch flows for domain + IPs
### FMC for domain + IPs
###

######################################################
##########
########## Call Module Files
##########
######################################################
import credential

from TB_AMP import *
from TB_AMPTOOLBOX import *
from TB_Logger import *
from TB_SPAM import *
from TB_TALOS import *
from TB_TG import *
from TB_Umbrella import *
from TB_VT import *

######################################################
##########
########## Function Interact with Spark with a Bot
##########
######################################################
def sendSparkGET(url):
    """
    This method is used for:
        -retrieving message text, when the webhook is triggered with a message
            -Getting the username of the person who posted the message if a command is recognized
    """
    request = urllib2.Request(url, headers={"Accept": "application/json", "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + credential.spark_bearer)
    contents = urllib2.urlopen(request).read()

    return contents

def sendSparkPOST(url, data):
    """
        This method is used for:
            -posting a message to the Spark room to confirm that a command was received and processed
    """
    request = urllib2.Request(url, json.dumps(data), headers={"Accept": "application/json", "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + credential.spark_bearer)
    contents = urllib2.urlopen(request).read()

    return contents


######################################################
##########
##########  MENU - Message parsing
##########
######################################################

@post('/')
def index(request):
    """
        When messages come in from the webhook, they are processed here.  The message text needs to be retrieved from Spark,
        using the sendSparkGet() function.  The message text is parsed.  If an expected command is found in the message,
        further actions are taken. i.e.
    """
    webhook = json.loads(request.body)
    print(webhook['data']['id'])
    result = sendSparkGET('https://api.ciscospark.com/v1/messages/{0}'.format(webhook['data']['id']))
    result = json.loads(result)

    msg = None
    validuser = False
    datalist = open("authorized-users.txt", "r")
    userlist = datalist.readline()

    if webhook['data']['personEmail'] != credential.bot_email:

        while userlist:
            if userlist.strip() == webhook['data']['personEmail']:
                validuser = True
            userlist = datalist.readline()

        in_message = result.get('text', '').lower()
        in_message = in_message.replace(credential.bot_name, '')

        logger.info(webhook['data']['personEmail'])
        logger.info(in_message)

        in_message = in_message.split(' ')

        if (in_message[0] == '/intel' and validuser == True):

            if (validators.domain(in_message[1]) and validuser == True):
                logger.info("DOMAIN!!")

                msg_odns = CHECK_DOMAIN_ODNS(in_message[1],"domain")
                msg_odns_mark = '###@Cisco Umbrella \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns_mark, "markdown": msg_odns_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

                msg_tg = CHECK_QUERY_TG(in_message[1],"domain")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_talos, msg_BC = TALOS_BLOCK_LIST(in_message[1],"domain")
                msg_talos_mark = '###@Cisco TALOS \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_talos_mark, "markdown": msg_talos_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_talos})
                msg_BC_mark = '###@BrightCloud \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_BC_mark, "markdown": msg_BC_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_BC})

                msg_vt = CHECK_DOMAIN_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

                msg_bl = CHECK_SPAM_BL(in_message[1],"domain")
                msg_bl_mark = '###@SPAM Block List \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl_mark, "markdown": msg_bl_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl})

            elif (validators.ipv4(in_message[1]) and validuser == True):
                logger.info("IP!!")

                msg_odns = CHECK_DOMAIN_ODNS(in_message[1],"ip")
                msg_odns_mark = '###@Cisco Umbrella \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns_mark, "markdown": msg_odns_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

                msg_tg = CHECK_QUERY_TG(in_message[1],"ip")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_talos = TALOS_BLOCK_LIST(in_message[1],"ip")
                msg_talos_mark = '###@Cisco TALOS \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_talos_mark, "markdown": msg_talos_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_talos})

                msg_vt = CHECK_IP_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

                msg_bl = CHECK_SPAM_BL(in_message[1], "ip")
                msg_bl_mark = '###@SPAM Block List \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl_mark, "markdown": msg_bl_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl})

            elif (len(in_message[1]) == 40 and validuser == True):
                logger.info("SHA1 Hash!!")

                msg_odns = CHECK_HASH_ODNS(in_message[1])
                msg_odns_mark = '###@Cisco Umbrella \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns_mark, "markdown": msg_odns_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

                msg_tg = CHECK_QUERY_TG(in_message[1],"hash")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_amp_mark = "###@Cisco AMP \n Use SHA-256 Hashes!"
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp_mark, "markdown": msg_amp_mark})

                msg_vt = CHECK_HASH_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

            elif (len(in_message[1]) == 64 and validuser == True):
                logger.info("SHA256 Hash!!")

                msg_odns = CHECK_HASH_ODNS(in_message[1])
                msg_odns_mark = '###@Cisco Umbrella \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns_mark, "markdown": msg_odns_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

                msg_tg = CHECK_QUERY_TG(in_message[1],"hash")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_amp= CHECK_AMPTOOLBOX(in_message[1])
                msg_amp_mark = '###@Cisco Talos/AMP \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp_mark, "markdown": msg_amp_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp})

                msg_vt = CHECK_HASH_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

            elif validuser == True:
                msg_mark = "###Invalid input!! \n Select command:\n- /intel [IP Address | Domains | Hashes]\n- /activity [Usernames | IP Address | Domains | Hashes]\n\n This tool was created with the intent to search Cisco Threat Intel, free market sources and security related activity on a Cisco Infrastructure. " \
                           "The current capabilities are searching IPs, Domains or File Hashes against Cisco Security Infrastructure.\n\n **Usage Examples:**" \
                           "\n- **IP:** /activity 1.1.1.1\n- **Domain:** /intel cisco.com\n- **File Hashes:** /intel 3372c1edab46837f1e973164fa2d726c5c5e17bcb888828ccd7c4dfcc234a370    _(*prefer SHA-256)_\n"
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})
            else:
                msg_mark = "###Unauthorized User!! \n Please contact Diego Soares - disoares@cisco.com to request Access\n"
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})

        elif (in_message[0] == '/activity' and validuser == True):
            msg_mark = "###UNDER CONSTRUCTION\n"
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})

        elif validuser == True:
            msg_mark = "###Invalid input!! \n Select command:\n- /intel [IP Address | Domains | Hashes]\n- /activity [Usernames | IP Address | Domains | Hashes]\n\n This tool was created with the intent to search Cisco Threat Intel, free market sources and security related activity on a Cisco Infrastructure. " \
                       "The current capabilities are searching IPs, Domains or File Hashes against Cisco Security Infrastructure.\n\n **Usage Examples:**" \
                       "\n- **IP:** /activity 1.1.1.1\n- **Domain:** /intel cisco.com\n- **File Hashes:** /intel 3372c1edab46837f1e973164fa2d726c5c5e17bcb888828ccd7c4dfcc234a370    _(*prefer SHA-256)_\n"
            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})
        else:
            msg_mark = "###Unauthorized User!! \n Please contact Diego Soares - disoares@cisco.com to request Access\n"
            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})

    datalist.close()

    return "true"

run_itty(server='wsgiref', host='0.0.0.0', port=10010)