
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
        response_json = response.json()

        if response.status_code == 200:
            data = response_json['data']['attributes']
            print(data['last_analysis_stats'])
            print(data['sha256'])
            print(data['first_seen_itw_date'])
            print(data['last_submission_date'])
            print(data['type_tag'])
        else:
            print("Error occurred while checking the IP address.")

    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", str(e))


headers = {
    'x-apikey': api_key,
    'accept': 'application/json'
}
urls = 'https://www.virustotal.com/api/v3/files/634438a50ae1990c4f8636801c410460'
call_api_virustotal(urls, headers)        
