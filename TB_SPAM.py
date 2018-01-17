from TB_Logger import *
import dns.resolver
import sys


######################################################
##########
########## Variables SPAM Black Lists
##########
######################################################
### IP Blacklists
bls = ['cbl.abuseat.org',
    'http.dnsbl.sorbs.net',
    'misc.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'web.dnsbl.sorbs.net',
    'dnsbl.sorbs.net',
    'dul.dnsbl.sorbs.net',
    'smtp.dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'sbl.spamhaus.org',
    'zen.spamhaus.org',
    'dbl.spamhaus.org',
    'pbl.spamhaus.org',
    'xbl.spamhaus.org',
    'phishing.rbl.msrbl.net',
    'spam.rbl.msrbl.net',
    'combined.rbl.msrbl.net',
    'dialups.mail-abuse.org',
    'rbl.spamlab.com',
    'dnsbl.inps.de',
    'ips.backscatterer.org',
    'multi.surbl.org',
    'bl.spamcop.net',
    'query.senderbase.org',
    'blacklist.woody.ch',
    'dnsbl.abuse.ch',
    'ubl.lashback.com',
    'bsb.spamlookup.net']


######################################################
##########
########## Check SPAM Blacklist
##########
######################################################
def CHECK_SPAM_BL (input_value,input):

    print_msg = ''
    loop_count = loop_count_1 = loop_count_2 = bl_count = 0

    if input == 'ip':
        for bl in bls:
            bl_count +=1
            try:
                my_resolver = dns.resolver.Resolver()
#                my_resolver.nameservers = ['208.67.222.222']
                my_resolver.timeout = 3
                query = '.'.join(reversed(str(input_value).split("."))) + "." + bl
                answers = my_resolver.query(query, "A")
                if loop_count_1 == 0:
                    print_msg = print_msg + 'IP: ' + input_value + ' IS listed in ' + bl + '\n'
                    loop_count_1 += 1
                else:
                    print_msg = print_msg + ', ' + bl
            except dns.resolver.NXDOMAIN:
                loop_count += 1
            except dns.resolver.NoAnswer:
                loop_count += 1
            except dns.resolver.Timeout:
                loop_count_2 += 1
#                print(bl)

        if loop_count > 0:
            print_msg = print_msg + 'IP not listed in ' + str(loop_count+loop_count_2) + ' Blacklists out of ' + str(bl_count)

    elif input == 'domain':
        for bl in bls:
            bl_count +=1
            try:
                my_resolver = dns.resolver.Resolver()
 #               my_resolver.nameservers = ['208.67.222.222']
                my_resolver.timeout = 3
                query = input_value + bl
                answers = my_resolver.query(query, "A")
                if loop_count_1 == 0:
                    print_msg = print_msg + 'IP: ' + input_value + ' IS listed in ' + bl + '\n'
                    loop_count_1 += 1
                else:
                    print_msg = print_msg + ', ' + bl
            except dns.resolver.NXDOMAIN:
                loop_count += 1
            except dns.resolver.NoAnswer:
                loop_count += 1
            except dns.resolver.Timeout:
                loop_count_2 += 1
#                print(bl)

        if loop_count > 0:
            print_msg = print_msg + 'IP not listed in ' + str(loop_count+loop_count_2) + ' Blacklists out of ' + str(bl_count)

    logger.info("SPAM BL OK!")
    print("SPAM BL OK!")

    return print_msg


######################################################
##########
########## If you want to test this file uncomment the nex section
##########
######################################################
'''

if sys.argv[1] == '-ip':
    msg_to_print = CHECK_SPAM_BL(sys.argv[2],"ip")
    print (msg_to_print)
elif sys.argv[1] == '-domain':
    msg_to_print = CHECK_SPAM_BL(sys.argv[2],"domain")
    print(msg_to_print)
else:
    print("Invalid Operation!")

#'''