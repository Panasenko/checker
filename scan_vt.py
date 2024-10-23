
import requests

def check_ip_on_virustotal(ip_address, api_key):
    url = f'https://www.virustotal.com/api/v3/domains/{ip_address}'

    headers = {
        'x-apikey': api_key
    }

    try:
        response = requests.get(url, headers=headers)
        response_json = response.json()

        if response.status_code == 200:
            data = response_json['data']
            
            if 'attributes' in data:
                attributes = data['attributes']
                country = attributes.get('country', 'Unknown')
                last_analysis_stats = attributes.get('last_analysis_stats')
                
                print(last_analysis_stats)
                print("Country:", country)
                
            else:
                print("No information available for the IP address.")

        else:
            print("Error occurred while checking the IP address.")

    except requests.exceptions.RequestException as e:
        print("An error occurred during the request:", str(e))


# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
api_key = 'd6c516e8c532da2c8d10062de712d320f4f0b6da7de92b451a358d6617540f0a'
ip_address = 'google.com'  # Replace with the IP address you want to check

check_ip_on_virustotal(ip_address, api_key)
