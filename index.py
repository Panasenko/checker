#!/bin/python3 

import re
import optparse
import requests

API_KEY = 'd6c516e8c532da2c8d10062de712d320f4f0b6da7de92b451a358d6617540f0a'
BASE_URL_VT = 'https://www.virustotal.com/api/v3/'

class Main(object):

    def __init__(self):
        self.option = Options()
        self.ValidIOC = ValidIOC()
        self.start()

    def checkList(self, ioc_list):
        array_results = []

        while ioc_list:
            results = self.ValidIOC.valid_iocs(ioc_list.pop(0))
            array_results.append(results)
        return array_results

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

    def validate_sha256(self, hash_value):
        sha256_pattern = r'^[a-fA-F0-9]{64}$'
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

        elif self.validate_sha256(option):
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
                "object": "option"
            }
            return response


class VirusTotal(object):

    @staticmethod
    def call_api_virustotal(url):
       
        
       return url
        # headers = {
        #     'x-apikey': API_KEY,
        #     'accept': 'application/json'
        # }
        #
        # try:
        #     response = requests.get(url, headers=headers)
        #
        #     print(response.text)
        #     return response.text
        #
        #
        #
        #     response_json = response.json()
        #
        #     if response.status_code == 200:
        #         data = response_json['data']
        #         return response_json
        #     else:
        #         print("Error occurred while checking the IP address.")
        #
        # except requests.exceptions.RequestException as e:
        #     print("An error occurred during the request:", str(e))

    @staticmethod
    def check_ip_vt(ip_address):
        url = BASE_URL_VT + '/ip_addresses/' + ip_address
        return VirusTotal.call_api_virustotal(url)

    @staticmethod
    def check_domain_vt(domain):
        url = BASE_URL_VT + '/domains/' + domain
        return VirusTotal.call_api_virustotal(url)

    @staticmethod
    def check_files_vt(file):
        url = BASE_URL_VT + '/files/' + file
        return VirusTotal.call_api_virustotal(url)


if __name__ == "__main__":
    main = Main()

