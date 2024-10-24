#!/bin/python3 

import os
import re
import optparse
import requests
from dotenv import load_dotenv

load_dotenv()

# API_KEY = 'd6c516e8c532da2c8d10062de712d320f4f0b6da7de92b451a358d6617540f0a'
# BASE_URL_VT = 'https://www.virustotal.com/api/v3/'

API_KEY = os.getenv("API_KEY")
BASE_URL_VT = os.getenv("BASE_URL_VT")

print(f"API_KEY: {API_KEY}")
print(f"BASE_URL_VT: {BASE_URL_VT}")


class Main(object):

    def __init__(self):
        self.option = Options()
        self.ValidIOC = ValidIOC()
        self.start()

    def checkList(self, ioc_list):

        array_ip_adress = []
        array_domains = []
        array_files = []

        array_errors = []

        while ioc_list:
            results = self.ValidIOC.valid_iocs(ioc_list.pop(0))

            if results['type'] == 'domain' and results["status"]:
                array_domains.append(results)
            elif results['type'] == 'ip' and results["status"]:
                array_ip_adress.append(results)
            elif results['type'] == 'hash' and results["status"]:
                array_files.append(results)
            else:
                array_errors.append(results)


        # print(len(array_results),len(array_errors))
        return {
            "valid_error": array_errors,
            "valid_success": [array_files, array_ip_adress, array_domains]
        }

    def start(self):
        file_path = self.option.opt_parser()
        ioc_list = self.ValidIOC.readFile(file_path)
        print(self.checkList(ioc_list))


class Options(object):

    def opt_parser(self):
        parser = optparse.OptionParser()
        parser.add_option("-f", "--file",
                          dest="file_path",
                          help="Add file path for chack")
        return self.check_input(parser)

    def check_input(self, parser):
        options = parser.parse_args()[0]

        if not options.file_path:
            mes = "[-] Please specify an interface, use -- help for more info."
            parser.error(mes)

        return options.file_path


class ValidIOC(object):

    def readFile(self, file_path):
        try:
            with open(file_path, 'r') as file:
                ioc_list = file.read().splitlines()
                print('Прочтено %s елементов' %len(ioc_list))
                return ioc_list

        except FileNotFoundError:
            print("Файл не найден!")

        except IOError:
            print("Ошибка ввода-вывода!")

    def validate_ip(self, ip):
        ip_pattern = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
        return bool(re.fullmatch(ip_pattern, ip))

    def validate_hashes(self, hash_value):
        sha256_pattern = '\b[A-Fa-f0-9]{32}\b|\b[A-Fa-f0-9]{40}\b|\b[A-Fa-f0-9]{64}\b'

        return bool(re.fullmatch(sha256_pattern, hash_value))

    def validate_domain(self, domain):
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return bool(re.fullmatch(domain_pattern, domain))

    def valid_iocs(self, option):
        if self.validate_ip(option):
            response = {
                "status": True,
                "type": "ip",
                "object": VirusTotal.check_ip_vt(option)
            }
            return response

        elif self.validate_hashes(option):
            response = {
                "status": True,
                "type": "hash",
                "object": VirusTotal.check_files_vt(option)
            }
            return response
            
        elif self.validate_domain(option):
            response = {
                "status": True,
                "type": "domain",
                "object": VirusTotal.check_domain_vt(option)
            }
            return response

        else:
            response = {
                "status": False,
                "type": "None",
                "object": option
            }
            return response


class VirusTotal(object):

    @staticmethod
    def call_api_virustotal(url):
        
        headers = {
            'x-apikey': API_KEY,
            'accept': 'application/json'
        }

        try:
            response = requests.get(url, headers=headers)
            response_json = response.json()

            if response.status_code == 200:
                data = response_json['data']
                return data
            else:
                print("Error occurred while checking the IP address.")

        except requests.exceptions.RequestException as e:
            print("An error occurred during the request:", str(e))

    @staticmethod
    def check_ip_vt(ip_address):
        url = BASE_URL_VT + '/ip_addresses/' + ip_address
        results = VirusTotal.call_api_virustotal(url)

        attr = results['attributes']
        return {
            'check_ip': ip_address,
            'last_analise': attr['last_analysis_stats'],
            'country': attr['country'],
            'whois': attr['whois'],
            'whois_date': attr['whois_date'],
            'last_analysis_date': attr['last_analysis_date'],
            'last_modification_date': attr['last_modification_date']
        }

    @staticmethod
    def check_domain_vt(domain):
        url = BASE_URL_VT + '/domains/' + domain
        results = VirusTotal.call_api_virustotal(url)
        attr = results['attributes']
        return {
            'check_domain': domain,
            'last_analise': attr['last_analysis_stats'],
            'last_dns_records_date': attr['last_dns_records_date'],
            'whois': attr['whois'],
            'whois_date': attr['whois_date'],
            'creation_date': attr['creation_date'],
            'last_update_date': attr['last_update_date'],
            'last_modification_date': attr['last_modification_date']
        }

    @staticmethod
    def check_files_vt(file):
        url = BASE_URL_VT + '/files/' + file
        results = VirusTotal.call_api_virustotal(url)
        attr = results['attributes']
        return {
            'check_hash': file,
            'last_analise': attr['last_analysis_stats'],
            'sha256': attr['sha256'],
            'md5': attr['md5'],
            'sha1': attr['sha1'],
            'type_tag': attr['type_tag'],
            'first_seen_itw_date': attr['first_seen_itw_date'],
            'last_submission_date': attr['last_submission_date'],
            'last_modification_date': attr['last_modification_date']
        }


if __name__ == "__main__":
    main = Main()

