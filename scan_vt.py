
import requests

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
api_key = 'd6c516e8c532da2c8d10062de712d320f4f0b6da7de92b451a358d6617540f0a'
ip_address = '8.8.8.8'  # Replace with the IP address you want to check
files = '634438a50ae1990c4f8636801c410460'  # Replace with the IP address you want to check
domain = 'google.com'  # Replace with the IP address you want to check
base_vt_url = 'https://www.virustotal.com/api/v3/'

def call_api_virustotal(url, headers):
    try:
        response = requests.get(url, headers=headers)

        # print(response.text)
        return response.text



        # response_json = response.json()
        #
        # if response.status_code == 200:
        #     data = response_json['data']
        #     return response_json
        # else:
        #     print("Error occurred while checking the IP address.")

    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", str(e))

def check_ip_vt(ip_address):
    url = base_vt_url + '/ip_addresses/' + ip_address

    headers = {
        'x-apikey': api_key,
        'accept': 'application/json'
    }

    return call_api_virustotal(url, headers)


def check_domain_vt(domain):
    url = base_vt_url + '/domains/' + domain

    headers = {
        'x-apikey': api_key,
        'accept': 'application/json'
    }

    return call_api_virustotal(url, headers)


def check_files_vt(file):
    url = base_vt_url + '/files/' + file

    headers = {
        'x-apikey': api_key,
        'accept': 'application/json'
    }

    return call_api_virustotal(url, headers)


# print(check_ip_vt(ip_address))
# print(check_domain_vt(domain))
print(check_files_vt(files))
