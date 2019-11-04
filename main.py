import re
import sys
import logging
import operator as ops
from ipaddress import ip_address, ip_network, ip_interface

from firewall import getFirewall

"""Modulo de lectura y parseo de IPs de los archivos de log del Zimbra ubicados 
nativamente en # /var/log/zimbra.log y # /opt/zimbra/log/audit.log """

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# define my regex
date_regex_1 = "^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3}\s"
date_regex_2 = "[A-Z][a-z][a-z] \d{2} \d{2}:\d{2}:\d{2}"

ip_regex = "\d{1,}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
network_regex = "\d{1,}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/.\d{0,1}"


def load_valid_ips(ip_path):
    valid_ips = []
    with open(ip_path, "r") as ips:
        for line in ips:
            ip = re.findall(network_regex, line)
            if ip:
                valid_ips.append(ip_network(ip[0]))

    return valid_ips


# /opt/zimbra/log/audit.log
def load_file_type1(log_file_path):
    complete_match_list = []
    # Opens my log file and saves in the object file
    file = open(log_file_path, "r")
    for line in file:
        for match in re.finditer('.*invalid password', line, re.S):
            match_text = match.group()
            complete_match_list.append(match_text)
    file.close()
    logger.debug("File {} loaded".format(log_file_path))
    return complete_match_list


# /var/log/zimbra.log
def load_file_type2(log_file_path):
    complete_match_list = []
    # Opens my log file and saves in the object file
    file = open(log_file_path, "r")
    for line in file:
        for match in re.finditer(
            ".*]: SASL LOGIN authentication failed:.*", line, re.S
        ):
            match_text = match.group()
            complete_match_list.append(match_text)
    file.close()
    logger.debug("File {} loaded".format(log_file_path))
    return complete_match_list


def parser(file):
    ip_dict = {}
    rep = []
    for line in file:
        ip = re.findall(ip_regex, line)
        date = re.findall(date_regex_1, line)
        if date == []:
            date = re.findall(date_regex_2, line)
        if ip in rep:
            ip_dict[ip_address(ip[0])] = date[0]
        rep.append(ip)
    return ip_dict


def check_ips(all_ips, valid_net_ips):
    good_ips = []
    for ip in all_ips:
        for valid_net in valid_net_ips:
            if ip in valid_net:
                good_ips.append(ip)
    bad_ips = [x for x in all_ips if x not in good_ips]
    logger.debug("List of ips to be blocked: {}".format(bad_ips))
    logger.debug("Total of IPs: {}".format(len(bad_ips)))
    return bad_ips

def ip_to_net(ips,range):
    nets_list = []
    for ip in ips:
        nets_list.append(ip_network(ip).supernet(new_prefix=range))
        
    return set(nets_list)

def main():
    
    fw = getFirewall()
    
    if  '--flush' in sys.argv[0:]:
        fw.finalizar()
        exit()
   
    valid_net_ips = load_valid_ips(r"whitelist.txt")

    #/var/log/zimbra.log
    ip_dict = parser(load_file_type2(r"zimbra.log"))
    
    #/opt/zimbra/log/audit.log
    ip_dict.update(parser(load_file_type1(r"audit.log")))


    ips_to_ban = check_ips(ip_dict.keys(), valid_net_ips)
    nets_to_ban = ip_to_net(ips_to_ban,21)

    if  '--dry-run' in sys.argv[0:]:
        print('List of Networks to be ban:',nets_to_ban)
        exit()
    
    fw.inicializar()
    fw.finalizar()       
    for net in nets_to_ban:
       fw.bloquear(net.__str__())
    
      
  
if __name__ == '__main__':
    main()
