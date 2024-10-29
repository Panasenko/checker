#!/bin/python3 

import os
import re
import optparse
import requests
from dotenv import load_dotenv
from prettytable import PrettyTable
import datetime

load_dotenv()

API_KEY = os.getenv("API_KEY")
BASE_URL_VT = os.getenv("BASE_URL_VT")

class Main:
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

            if results["type"] == "domain" and results["status"]:
                array_domains.append(results)
            elif results["type"] == "ip" and results["status"]:
                array_ip_adress.append(results)
            elif results["type"] == "hash" and results["status"]:
                array_files.append(results)
            else:
                array_errors.append(results)

        return {
            "valid_error": array_errors,
            "valid_success": {
                "hash": array_files,
                "ip": array_ip_adress,
                "domain": array_domains,
            },
        }
        

    def start(self):
        file_path = self.option.opt_parser()
        ioc_list = self.ValidIOC.readFile(file_path)
        array_ioc = self.checkList(ioc_list)
        report = Report(array_ioc)

        print(report.build_report_ips())
        print(report.build_report_domains())
        print(report.build_report_files())
        print(report.build_report_error())



class Options:
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


class ValidIOC:
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
        hash_pattern = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
        return bool(re.fullmatch(hash_pattern, hash_value))

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


class VirusTotal:
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
        # url = BASE_URL_VT + '/ip_addresses/' + ip_address
        url = f"{BASE_URL_VT}/ip_addresses/{ip_address}"
        results = VirusTotal.call_api_virustotal(url)

        # TODO: Need make check respons 

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
        url = f"{BASE_URL_VT}/domains/{domain}"
        # url = BASE_URL_VT + '/domains/' + domain
        results = VirusTotal.call_api_virustotal(url)
        # TODO: Need make check respons 
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
        url = f"{BASE_URL_VT}/files/{file}"
        # url = BASE_URL_VT + '/files/' + file
        results = VirusTotal.call_api_virustotal(url)
        # TODO:  Need make check respons 
        attr = results['attributes']
        return {
            'check_hash': file,
            'last_analise': attr['last_analysis_stats'],
            'sha256': attr['sha256'],
            'md5': attr['md5'],
            'sha1': attr['sha1'],
            'type_tag': attr['type_tag'],
            'last_submission_date': attr['last_submission_date'],
            'last_modification_date': attr['last_modification_date']
        }


class Report:
    def __init__(self, array_ioc):
        self.valid_error = array_ioc['valid_error'] 
        self.array_files = array_ioc['valid_success']["hash"]
        self.array_ip_adress = array_ioc['valid_success']['ip']
        self.array_domains = array_ioc['valid_success']['domain']

    def build_report_ips(self):
        table = PrettyTable()

        if bool(len(self.array_ip_adress)):

            table.field_names = ["IP adress", "VT malicious", "VT suspicious", "Country", "Whois date",  "VT last analysis date"]
            array_ip = self.array_ip_adress

            for value in array_ip:
                v = value["object"]
                fromated_data = [v["check_ip"], v["last_analise"]["malicious"], v["last_analise"]["suspicious"], v["country"], self.convert_date(v["whois_date"]), self.convert_date(v["last_modification_date"])]
                table.add_row(fromated_data)
            return table


    def build_report_domains(self):
        table = PrettyTable()

        if bool(len(self.array_domains)):
            table.field_names = ["Domain", "VT malicious", "VT suspicious", "DNS record", "Whois date",  "Create date"]
            array_domains = self.array_domains

            for value in array_domains:
                v = value["object"]
                fromated_data = [v["check_domain"], v["last_analise"]["malicious"], v["last_analise"]["suspicious"], self.convert_date(v["last_dns_records_date"]), self.convert_date(v["whois_date"]), self.convert_date(v["creation_date"])]
                table.add_row(fromated_data)
            return table

    def build_report_files(self):
        table = PrettyTable()

        if bool(len(self.array_files)):
            table.field_names = ["Hash file", "Type tag", "VT malicious", "VT suspicious", "sha256", "Last submission", "Last modification"]
            array_files = self.array_files

            for value in array_files:
                v = value["object"]
                fromated_data = [v["check_hash"], v["type_tag"] , v["last_analise"]["malicious"], v["last_analise"]["suspicious"], v["sha256"], self.convert_date(v["last_submission_date"]), self.convert_date(v["last_modification_date"])]
                table.add_row(fromated_data)
            return table


    def build_report_error(self):
        table = PrettyTable()

        if bool(len(self.valid_error)):
            table.field_names = ["Invalid data"]

            for value in self.valid_error:
                table.add_row([value["object"]])
            return table


    def convert_date(self, timestamp):
        value = datetime.datetime.fromtimestamp(timestamp)
        return value.strftime('%d %B %Y')


if __name__ == "__main__":
    main = Main()

