import re
from pprint import pprint
log_file_path = r"template.log"
regex = '^\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3}\sWARN.*$'

match_list = []
with open(log_file_path, "r") as file:
    for line in file:
        for match in re.finditer(regex, line, re.S):
            match_text = match.group()
            match_list.append(match_text)
            print(match_text)

#    pprint(match_list)
