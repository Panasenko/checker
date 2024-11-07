# Python program to demonstrate
# Conversion of JSON data to
# dictionary

# importing the module
import json


ATTR_REQUEST_HASH = ['last_analysis_stats', 'sha256', 'md5','sha1','type_tag','last_submission_date','last_modification_date']
ATTR_REQUEST_IP = ['last_analysis_stats', 'country', 'whois', 'whois_date','last_analysis_date','last_modification_date']
ATTR_REQUEST_DOMAIN = ['last_analysis_stats','last_dns_records_date','whois','whois_date','creation_date', 'last_update_date','last_modification_date']

# Opening JSON file
with open('jsondata.json') as json_file:
    data = json.load(json_file)

    # Print the type of data variable
    print("Type:", type(data))


def set_response(data, pattern):
    array_res = {}
    for item in pattern:
        array_res[item] = data[item]
    return array_res

print(set_response(data["data"]["attributes"], ATTR_REQUEST_DOMAIN))        
