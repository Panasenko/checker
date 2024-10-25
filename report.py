
from prettytable import PrettyTable
import datetime
table = PrettyTable()

array_ioc = {'valid_error': [{'status': False, 'type': 'None', 'object': 'e11e8b39f785b2184f68369e2e1300530572725073e66117b83be0a84f82355'}], 'valid_success': {'hash': [{'status': True, 'type': 'hash', 'object': {'check_hash': '634438a50ae1990c4f8636801c410460', 'last_analise': {'malicious': 6, 'suspicious': 0, 'undetected': 50, 'harmless': 0, 'timeout': 0, 'confirmed-timeout': 0, 'failure': 1, 'type-unsupported': 15}, 'sha256': 'b8a609caefd4df29c0a251bb326c30f7c58793d2d353daefc0970f471e23e7b6', 'md5': '634438a50ae1990c4f8636801c410460', 'sha1': '43cd3b2a205db4a69f6df88cd4aa4581a1822582', 'type_tag': 'text', 'last_submission_date': 1447957525, 'last_modification_date': 1721366641}}, {'status': True, 'type': 'hash', 'object': {'check_hash': 'a27f261247f766346d57e2fdedc167f574d13c9820986e92752df05e380c2972', 'last_analise': {'malicious': 63, 'suspicious': 0, 'undetected': 6, 'harmless': 0, 'timeout': 0, 'confirmed-timeout': 0, 'failure': 0, 'type-unsupported': 5}, 'sha256': 'a27f261247f766346d57e2fdedc167f574d13c9820986e92752df05e380c2972', 'md5': '18557f571ab13a1f4365de8a15d26e12', 'sha1': 'bcbf1c2b462fe92432185c648fc335a5c9d193e2', 'type_tag': 'peexe', 'last_submission_date': 1522707894, 'last_modification_date': 1637031277}}, {'status': True, 'type': 'hash', 'object': {'check_hash': 'f846301e7f190ee3bb2d3821971cc2456617edc2060b07729415c45633a5a751', 'last_analise': {'malicious': 39, 'suspicious': 0, 'undetected': 19, 'harmless': 0, 'timeout': 0, 'confirmed-timeout': 0, 'failure': 1, 'type-unsupported': 15}, 'sha256': 'f846301e7f190ee3bb2d3821971cc2456617edc2060b07729415c45633a5a751', 'md5': '4bd06656456db81a362426236c22a7bc', 'sha1': '60a1c15380eeb2a54c122803822508ce3ed972d6', 'type_tag': 'rar', 'last_submission_date': 1522707936, 'last_modification_date': 1716167289}}], 'ip': [{'status': True, 'type': 'ip', 'object': {'check_ip': '45.137.116.8', 'last_analise': {'malicious': 4, 'suspicious': 2, 'undetected': 31, 'harmless': 57, 'timeout': 0}, 'country': 'RU', 'whois': 'inetnum: 45.137.116.0 - 45.137.117.255\nnetname: IPXO\ncountry: GB\norg: ORG-IL687-RIPE\nadmin-c: NOC834\ntech-c: NOC834\nabuse-c: IPXO834\nstatus: SUB-ALLOCATED PA\nmnt-by: IPXO-MNT\ncreated: 2022-03-10T12:14:45Z\nlast-modified: 2022-03-10T12:14:45Z\nsource: RIPE\norganisation: ORG-IL687-RIPE\norg-name: Internet Utilities Europe and Asia Limited\norg-type: LIR\naddress: Regent street 207\naddress: W1B 3HH\naddress: London\naddress: UNITED KINGDOM\ncountry: GB\nphone: +370 699 08833\nadmin-c: NOC834\ntech-c: NOC834\nabuse-c: IPXO834\nmnt-ref: IPXO-MNT\nmnt-by: RIPE-NCC-HM-MNT\nmnt-by: IPXO-MNT\ncreated: 2021-04-28T09:11:24Z\nlast-modified: 2024-07-23T13:36:03Z\nsource: RIPE # Filtered\nrole: IPXO Admin/Tech Contact\naddress: Ground Floor, 4 Victoria Square, St Albans, Hertfordshire, AL1 3TF, UK\nnic-hdl: NOC834\nmnt-by: IPXO-MNT\ncreated: 2021-07-27T09:53:47Z\nlast-modified: 2021-07-29T08:24:01Z\nsource: RIPE # Filtered\nroute: 45.137.116.0/24\norigin: AS30823\nmnt-by: IPXO-MNT\ncreated: 2020-09-09T14:34:31Z\nlast-modified: 2023-04-17T12:06:43Z\nsource: RIPE\n', 'whois_date': 1727349218, 'last_analysis_date': 1729667292, 'last_modification_date': 1729764459}}], 'domain': [{'status': True, 'type': 'domain', 'object': {'check_domain': 'cflayerprotection.com', 'last_analise': {'malicious': 13, 'suspicious': 1, 'undetected': 28, 'harmless': 52, 'timeout': 0}, 'last_dns_records_date': 1727749654, 'whois': 'Administrative email: 0861d1d8a4fe2ca7s@domprivacy.de\nCreate date: 2023-11-15 00:00:00\nDomain name: cflayerprotection.com\nDomain registrar id: 1443\nDomain registrar url: http://www.vautron.de\nExpiry date: 2024-11-15 00:00:00\nName server 1: deb.ns.cloudflare.com\nName server 2: george.ns.cloudflare.com\nQuery time: 2023-11-16 11:01:55\nRegistrant country: Bangladesh\nRegistrant email: 0861d1d8a4fe2ca7s@domprivacy.de\nRegistrant state: 3195714afd2c547c\nTechnical email: 81ffb2b821b6cc2ds@domprivacy.de\nUpdate date: 2023-11-16 00:00:00', 'whois_date': 1731628800, 'creation_date': 1700006400, 'last_update_date': 1700092800, 'last_modification_date': 1729770834}}]}}


class Report:
    def __init__(self, array_ioc):
        self.valid_error = array_ioc['valid_error'] 
        self.array_files = array_ioc['valid_success']["hash"]
        self.array_ip_adress = array_ioc['valid_success']['ip']
        self.array_domains = array_ioc['valid_success']['domain']

    # def build_report_ips(self):
    #     table = PrettyTable()
    #
    #     if bool(len(self.array_ip_adress)):
    #
    #         table.field_names = ["IP adress", "VT malicious", "VT suspicious", "Country", "Whois date",  "VT last analysis date"]
    #         array_ip = self.array_ip_adress
    #
    #         for value in array_ip:
    #             v = value["object"]
    #             fromated_data = [v["check_ip"], v["last_analise"]["malicious"], v["last_analise"]["suspicious"], v["country"], self.convert_date(v["whois_date"]), self.convert_date(v["last_modification_date"])]
    #             table.add_row(fromated_data)
    #         return table
    #
    #
    # def build_report_domains(self):
    #     table = PrettyTable()
    #
    #     if bool(len(self.array_domains)):
    #         table.field_names = ["Domain", "VT malicious", "VT suspicious", "DNS record", "Whois date",  "Create date"]
    #         array_domains = self.array_domains
    #
    #         for value in array_domains:
    #             v = value["object"]
    #             fromated_data = [v["check_domain"], v["last_analise"]["malicious"], v["last_analise"]["suspicious"], self.convert_date(v["last_dns_records_date"]), self.convert_date(v["whois_date"]), self.convert_date(v["creation_date"])]
    #             table.add_row(fromated_data)
    #         return table
    #
    # def build_report_files(self):
    #     table = PrettyTable()
    #
    #     if bool(len(self.array_files)):
    #         table.field_names = ["Hash file", "Type tag", "VT malicious", "VT suspicious", "sha256", "Last submission", "Last modification"]
    #         array_files = self.array_files
    #
    #         for value in array_files:
    #             v = value["object"]
    #             fromated_data = [v["check_hash"], v["type_tag"] , v["last_analise"]["malicious"], v["last_analise"]["suspicious"], v["sha256"], self.convert_date(v["last_submission_date"]), self.convert_date(v["last_modification_date"])]
    #             table.add_row(fromated_data)
    #         return table
    #
    #
    def build_report_error(self):
        table = PrettyTable()

        if bool(len(self.valid_error)):
            print(self.valid_error)
            table.field_names = ["Invalid data"]

            for value in self.valid_error:
                v = [value["object"]]
                table.add_row(v)
            return table


    def convert_date(self, timestamp):
        value = datetime.datetime.fromtimestamp(timestamp)
        return value.strftime('%d %B %Y')



report = Report(array_ioc)


# print(report.build_report_ips())
# print(report.build_report_domains())
# print(report.build_report_files())
print(report.build_report_error())
