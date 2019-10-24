import re
from pprint import pprint
import operator as ops
from ipaddress import ip_address, ip_network
import itertools


#defines my regex
date_regex = '^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3}\s'
ip_regex = '\d{1,}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
network_regex = '\d{1,}\.\d{1,3}\.\d{1,3}\.\d{1,3}/]?[0-9][0-9]'
complete_match_list = []
ip_dict = {}

def load_valid_ips(ip_path):
    valid_ips = []
    with open(ip_path, "r") as ips:
       for line in ips:
            ip = re.findall(network_regex, line)
            valid_ips.append(ip_network(ip[0]))
            
    return valid_ips


def parser(log_file_path):
    #Opens my log file and saves in the object file
    with open(log_file_path, "r") as file:
        for line in file:
            for match in re.finditer(date_regex +'WARN.*$', line, re.S):
                match_text = match.group()
                complete_match_list.append(match_text)
                ip = re.findall(ip_regex, match_text)
                date = re.findall(date_regex, match_text)
                ip_dict[ip_address(ip[0])] = date[0]
    return ip_dict

def check_ips(all_ips, valid_net_ips):
    all_ips = ip_dict.keys()
    good_ips = []
    for ip in all_ips:
        for valid_net in valid_net_ips:
            if ip in valid_net:          
                good_ips.append(ip)
    bad_ips = all_ips - good_ips
    return bad_ips


valid_net_ips = load_valid_ips(r"valid_ips.txt")
ip_dict = parser(r"template.log")

pprint(len(ip_dict.keys()))