import json
import requests
import validators
from http.server import BaseHTTPRequestHandler, HTTPServer

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
from TB_CTR import *

######################################################
##########
########## Function Interact with Spark with a Bot
##########
######################################################
def sendSparkGET(url):
    header = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer '+credential.spark_bearer}
    request = requests.get(url,headers=header, verify=False)
    request_json = request.json()
    
    return (request_json)

def sendSparkPOST(url, payload):
    header = {'Accept': 'application/json', 'Content-Type': 'application/json', 'Authorization': 'Bearer '+credential.spark_bearer}
    request = requests.post(url, json=payload, headers=header, verify=False)
    request_json = request.json()

    return (request_json)


######################################################
##########
##########  MENU - Message parsing
##########
######################################################
def index(webhook):

    msg_url = 'https://api.ciscospark.com/v1/messages/'+str(webhook['data']['id'])
    result = sendSparkGET(msg_url)

    msg = None
    validuser = False
    payload ={}
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

                msg_tg = CHECK_INTEL_TG(in_message[1],"domain")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_vt = CHECK_DOMAIN_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

                msg_bl = CHECK_SPAM_BL(in_message[1],"domain")
                msg_bl_mark = '###@SPAM Block List \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl_mark, "markdown": msg_bl_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl})

                msg_ctr = RUN_CTR(in_message[1])
                msg_visibility_mark = '###@Cisco Threat Response \n'
                msg_visibility = 'Want a nice GUI to investigate '+in_message[1]+' go to https://visibility.amp.cisco.com/#/investigate?q='+in_message[1]
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": str(msg_ctr)})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility})


            elif (validators.ipv4(in_message[1]) and validuser == True):
                logger.info("IP!!")

                msg_odns = CHECK_DOMAIN_ODNS(in_message[1],"ip")
                msg_odns_mark = '###@Cisco Umbrella \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns_mark, "markdown": msg_odns_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

                msg_tg = CHECK_INTEL_TG(in_message[1],"ip")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_vt = CHECK_IP_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

                msg_bl = CHECK_SPAM_BL(in_message[1], "ip")
                msg_bl_mark = '###@SPAM Block List \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl_mark, "markdown": msg_bl_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_bl})

                msg_ctr = RUN_CTR(in_message[1])
                msg_visibility_mark = '###@Cisco Threat Response \n'
                msg_visibility = 'Want a nice GUI to investigate '+in_message[1]+' go to https://visibility.amp.cisco.com/#/investigate?q='+in_message[1]
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": str(msg_ctr)})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility})

            elif (len(in_message[1]) == 40 and validuser == True):
                logger.info("SHA1 Hash!!")

                msg_odns = CHECK_HASH_ODNS(in_message[1])
                msg_odns_mark = '###@Cisco Umbrella \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns_mark, "markdown": msg_odns_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

                msg_tg = CHECK_INTEL_TG(in_message[1],"hash")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_amp_mark = "###@Cisco AMP \n Use SHA-256 Hashes!"
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp_mark, "markdown": msg_amp_mark})

                msg_vt = CHECK_HASH_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

                msg_ctr = RUN_CTR(in_message[1])
                msg_visibility_mark = '###@Cisco Threat Response \n'
                msg_visibility = 'Want a nice GUI to investigate '+in_message[1]+' go to https://visibility.amp.cisco.com/#/investigate?q='+in_message[1]
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": str(msg_ctr)})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility})

            elif (len(in_message[1]) == 64 and validuser == True):
                logger.info("SHA256 Hash!!")

                msg_odns = CHECK_HASH_ODNS(in_message[1])
                msg_odns_mark = '###@Cisco Umbrella \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns_mark, "markdown": msg_odns_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_odns})

                msg_tg = CHECK_INTEL_TG(in_message[1],"hash")
                msg_tg_mark = '###@Cisco ThreatGrid \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg_mark, "markdown": msg_tg_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_tg})

                msg_amp= CHECK_AMPTOOLBOX(in_message[1])
                msg_amp_mark = '###@Cisco AMP \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp_mark, "markdown": msg_amp_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp})

                msg_vt = CHECK_HASH_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

                msg_ctr = RUN_CTR(in_message[1])
                msg_visibility_mark = '###@Cisco Threat Response \n'
                msg_visibility = 'Want a nice GUI to investigate '+in_message[1]+' go to https://visibility.amp.cisco.com/#/investigate?q='+in_message[1]
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": str(msg_ctr)})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility})

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
            sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})
        else:
            msg_mark = "###Unauthorized User!! \n Please contact Diego Soares - disoares@cisco.com to request Access\n"
            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})

    datalist.close()

    logger.info("Executed!")
    return "Executed."

class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_response()
        self.wfile.write("GET request for {}".format(self.path).encode('utf-8'))

 	    # POST valida se o que chega sem dados via o Webhook
   	    # do POST e' que se chama a rotina de respnder ao usuario

    def do_POST(self):
        post_data = self.rfile.read(int(self.headers.getheader('Content-Length'))) # <--- Gets the data itself
        self._set_response()

        content = json.loads(post_data.decode('utf-8'))
        print(index(content))

def run(server_class=HTTPServer, handler_class=S, port=10010):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print ('Starting Threatbot WEB Listener...')
    httpd.serve_forever()

run()