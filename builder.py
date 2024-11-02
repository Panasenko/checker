#!/bin/python3

import os
import re
from abc import ABC, abstractmethod
from dotenv import load_dotenv

load_dotenv()


class Indicators:
    IP_PATTERN = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    HASH_PATTERN = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
    DOMAIN_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    def __init__(self, indicator: str) -> None:
        self.indicator = indicator
        self._status_valid = False
        self._type_indicator: str

        self.valid_indicators(self.indicator)

    def get_indicator(self) -> str:
        return self.indicator
    
    def get_status_valid(self) -> bool:
        return self._status_valid

    def set_status_valid(self, value: bool):
        self._status_valid = value

    def get_type_indicator(self) -> str:
        return self._type_indicator

    def set_type_indicator(self, value: str):
        self._type_indicator = value

    def validate_ip_address(self, value) -> bool:
        return bool(re.fullmatch(self.IP_PATTERN, value))

    def validate_hashes(self, value) -> bool:
        return bool(re.fullmatch(self.HASH_PATTERN, value))

    def validate_domain(self, value) -> bool:
        return bool(re.fullmatch(self.DOMAIN_PATTERN, value))

    def valid_indicators(self, option: str):
        if self.validate_ip_address(option):
            self.set_status_valid(True)
            self.set_type_indicator("ip_address")

        elif self.validate_hashes(option):
            self.set_status_valid(True)
            self.set_type_indicator("hash_file")

        elif self.validate_domain(option):
            self.set_status_valid(True)
            self.set_type_indicator("domain")
        else:
            self.set_type_indicator("no_valid")

indicator = Indicators("192.168.50.123")
print(indicator.get_status_valid())

class RequestBilder:
    def __init__(self, indicator: Indicators):
        self.indicator = indicator
        print(self.indicator.get_type_indicator())

    def get_object(self):
        #TODO: Добавить проверку на ошибки
        return self.RequestFactory.create_request(self.indicator)

    class RequestVirusTotal(ABC):

        BASE_URL_VT = os.getenv("BASE_URL_VT")
        HEADER = {
            'x-apikey': os.getenv("API_KEY"),
            'accept': 'application/json'
        }

        def __init__(self, indicator: str) -> None:
                self.indicator = indicator

        @abstractmethod
        def get_url (self) -> str:
            pass

    class RequestHash(RequestVirusTotal):
        def __init__(self, indicator: str) -> None:
            super().__init__(indicator)
         
        def get_url(self):
            # print(f"${super().BASE_URL_VT}")
            return f"${super().BASE_URL_VT}"

    class RequestIPAdress(RequestVirusTotal):
        def __init__(self, indicator: str) -> None:
            super().__init__(indicator)

        def get_url(self):
            # print(f"${super().BASE_URL_VT}")
            return f"${super().BASE_URL_VT}"

    class RequestDomain(RequestVirusTotal):
        def __init__(self, indicator: str) -> None:
            super().__init__(indicator)

        def get_url(self):
            return f"${super().BASE_URL_VT}"

    class RequestFactory:
        @staticmethod
        def create_request(indicator: Indicators):
            if indicator.get_type_indicator() == "hash_file":
                return RequestBilder.RequestHash(indicator.get_indicator())

            elif indicator.get_type_indicator() == "ip_address":
                return RequestBilder.RequestIPAdress(indicator.get_indicator())

            elif indicator.get_type_indicator() == "domain":
                return RequestBilder.RequestDomain(indicator.get_indicator())
            else:
                raise ValueError("Unknown type of Indicators")


request = RequestBilder(indicator)
# print(request.get_object()e())
i = request.get_object()
print(i.get_url())
