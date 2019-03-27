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

######################################################
##########
########## Function Interact with Spark with a Bot
##########
######################################################
def sendSparkGET(url):
    """
    This method is used for:
        - Retrieving message text, when the webhook is triggered with a message
        - Getting the username of the person who posted the message if a command is recognized
    
    request = urllib2.Request(url, headers={"Accept": "application/json", "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + credential.spark_bearer)
    contents = urllib2.urlopen(request).read()
    """
    print("GET Message")
    logger.info("GET Message")

    request = requests.get(url,headers={"Accept": "application/json", "Content-Type": "application/json", "Authorization": "Bearer "+credential.spark_bearer}, verify=False)
    request_json = request.json()
    
    return (request_json)

def sendSparkPOST(url, data):
    """
    This method is used for:
        - Posting a message to the Spark room to confirm that a command was received and processed
    
    request = urllib2.Request(url, json.dumps(data), headers={"Accept": "application/json", "Content-Type": "application/json"})
    request.add_header("Authorization", "Bearer " + credential.spark_bearer)
    contents = urllib2.urlopen(request).read()
    """
    request = requests.post(url,data=data, headers={"Accept": "application/json", "Content-Type": "application/json", "Authorization": "Bearer "+credential.spark_bearer}, verify=False)
    request_json = request.json()

    return (request_json)


######################################################
##########
##########  MENU - Message parsing
##########
######################################################
def index(webhook):
    """
        When messages come in from the webhook, they are processed here.  The message text needs to be retrieved from Spark,
        using the sendSparkGet() function.  The message text is parsed.  If an expected command is found in the message,
        further actions are taken. i.e.
    """
    print("BEGIN")
    print(webhook['data']['id'])
    result = sendSparkGET('https://api.ciscospark.com/v1/messages/{0}'.format(webhook['data']['id']))

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

                msg_tg = CHECK_INTEL_TG(in_message[1],"domain")
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

                msg_visibility_mark = '###@AMP Visibility \n'
                msg_visibility = 'Want a nice GUI to investigate '+in_message[1]+' go to https://visibility.amp.cisco.com/#/investigate?q='+in_message[1]
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
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

                msg_talos, msg_BC = TALOS_BLOCK_LIST(in_message[1],"ip")
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

                msg_visibility_mark = '###@AMP Visibility \n'
                msg_visibility = 'Want a nice GUI to investigate '+in_message[1]+' go to https://visibility.amp.cisco.com/#/investigate?q='+in_message[1]
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
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

                msg_visibility_mark = '###@AMP Visibility \n'
                msg_visibility = 'CISCO AMP does not support weak SHA1 Hash'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
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
                msg_amp_mark = '###@Cisco Talos/AMP \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp_mark, "markdown": msg_amp_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_amp})

                msg_vt = CHECK_HASH_VT(in_message[1])
                msg_vt_mark = '###@Virus Total \n'
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt_mark, "markdown": msg_vt_mark})
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_vt})

                msg_visibility_mark = '###@AMP Visibility \n'
                msg_visibility = 'Want a nice GUI to investigate '+in_message[1]+' go to https://visibility.amp.cisco.com/#/investigate?q='+in_message[1]
                sendSparkPOST("https://api.ciscospark.com/v1/messages", {"roomId": webhook['data']['roomId'], "text": msg_visibility_mark, "markdown": msg_visibility_mark})
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
            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})
        else:
            msg_mark = "###Unauthorized User!! \n Please contact Diego Soares - disoares@cisco.com to request Access\n"
            sendSparkPOST("https://api.ciscospark.com/v1/messages",
                          {"roomId": webhook['data']['roomId'], "text": msg_mark, "markdown": msg_mark})

    datalist.close()

    return "true"

class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("<html><body><h1>ThreatBot Listener!</h1></body></html>")

    def do_HEAD(self):
        self._set_headers()
        
    def do_POST(self):
        content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
        post_data = self.rfile.read(content_length) # <--- Gets the data itself
        logging.info("POST request,\nPath: %s\nHeaders:\n%s\n\nBody:\n%s\n", str(self.path), str(self.headers), post_data.decode('utf-8'))
        self._set_response()
        self.wfile.write("POST request for {}".format(self.path).encode('utf-8'))

        content=json.loads(post_data.decode('utf-8'))
        execution_response = index(content)
        print (execution_response)

def run(server_class=HTTPServer, handler_class=S, port=10010):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting Threatbot WEB Listener...'
    httpd.serve_forever()

run()