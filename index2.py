#!/bin/python3

import typer
import sys
import re
import os
import logging
import aiohttp
import asyncio
import datetime

from abc import ABC, abstractmethod
from dotenv import load_dotenv
from rich import print
from rich.table import Table
from rich.style import Style

#TODO: Расставить логинки по всем методам
load_dotenv()
logging.basicConfig(level=logging.ERROR)

def main(input_file: typer.FileText = typer.Argument(None, help="Входной файл (опционально)")):
    """
    Main function to read input data from a file or stdin and pass it to the scheduler function.

    Parameters:
    input_file (typer.FileText): An optional argument representing the input file to read data from.

    Returns:
    None

    Raises:
    None
    """
    if input_file:
        scheduler(input_file.read())
    elif not sys.stdin.isatty():
        scheduler(sys.stdin.read())
    else:
        typer.echo("Не предоставлено ни файла, ни данных через stdin.")

def scheduler(content: str):
    array_requests_objects = []
    array_novalid_objects = []

    for line in content.splitlines():
        
        indicator_object = Indicators(line)

        if indicator_object.get_status_valid():
            request = RequestBuilder(indicator_object)
            request_object = request.get_object()

            if request_object is not None:
                array_requests_objects.append(request_object)
        else:
            array_novalid_objects.append(indicator_object)

    call_api = CallAPI(array_requests_objects)
    asyncio.run(call_api.caller())

    print(call_api.__dict__)

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

    def _validate_ip_adress(self, value) -> bool:
        return bool(re.fullmatch(self.IP_PATTERN, value))

    def _validate_hashes(self, value) -> bool:
        return bool(re.fullmatch(self.HASH_PATTERN, value))

    def _validate_domain(self, value) -> bool:
        return bool(re.fullmatch(self.DOMAIN_PATTERN, value))

    def valid_indicators(self, option: str):
        if self._validate_ip_adress(option):
            self.set_status_valid(True)
            self.set_type_indicator("ip_address")

        elif self._validate_hashes(option):
            self.set_status_valid(True)
            self.set_type_indicator("hash_file")

        elif self._validate_domain(option):
            self.set_status_valid(True)
            self.set_type_indicator("domain")
        else:
            self.set_type_indicator("no_valid")

class RequestBuilder:
        def __init__(self, indicator: Indicators) -> None:
            self.indicator = indicator

        def get_indicator(self) -> Indicators:
            return self.indicator

        def get_object(self):
            try:
                request_object = self.RequestFactory.create_request(self.indicator)
            except ValueError as e:
                logging.error(f"Создание обьекта класса RequestFactory заверщилось ошибкой: {e}. Обработка индикатора {self.indicator.get_indicator()}")
                return None
            else:
                return request_object

        class RequestVirusTotal(ABC):
            BASE_URL_VT = os.getenv("BASE_URL_VT")
            HEADER = {'x-apikey': os.getenv("API_KEY"), 'accept': 'application/json'}
            
            def __init__(self, indicator: str) -> None:
                self.indicator = indicator
                self._response: dict

            @abstractmethod
            def get_url(self) -> str:
                pass
            
            @abstractmethod
            def get_header(self) -> dict:
                pass

            def set_response(self, response: dict, fields: list):
                dict_response = {}
                if bool(response and fields):
                    for item in fields:
                        if item == "last_analysis_stats":
                            dict_response.update(response.pop('last_analysis_stats'))
                        else:
                            dict_response[item] = response[item]
                self._response = dict_response

            @abstractmethod
            def get_fields(self) -> list:
                pass

            def get_response(self)-> dict:
                return self._response

        class RequestHash(RequestVirusTotal):
            def __init__(self, indicator: str) -> None:
                super().__init__(indicator) 
                self.url = f"{super().BASE_URL_VT}files/{self.indicator}" 

            def set_response(self, response: dict, fields: list):
                super().set_response(response, fields)

            def get_response(self)-> dict:
                return self._response

            def get_header(self) -> dict:
                return super().HEADER

            def get_url(self) -> str:
                return self.url
        
            def get_fields(self) -> list:
                return ['last_analysis_stats', 'sha256', 'md5','sha1','type_tag','last_submission_date','last_modification_date']

        class RequestIPAdress(RequestVirusTotal):
            def __init__(self, indicator: str) -> None:
                super().__init__(indicator)
                self.url = f"{super().BASE_URL_VT}ip_addresses/{self.indicator}"

            def set_response(self, response: dict, fields: list):
                super().set_response(response, fields)

            def get_response(self)-> dict:
                return self._response

            def get_header (self) -> dict:
                return super().HEADER

            def get_url(self) -> str:
                return self.url

            def get_fields(self) -> list:
                return ['last_analysis_stats', 'country', 'whois', 'whois_date','last_analysis_date','last_modification_date']

        class RequestDomain(RequestVirusTotal):
            def __init__(self, indicator: str) -> None:
                super().__init__(indicator)
                self.url = f"{super().BASE_URL_VT}domains/{self.indicator}"

            def set_response(self, response: dict, fields: list):
                super().set_response(response, fields)

            def get_response(self)-> dict:
                return self._response

            def get_header(self) -> dict:
                return super().HEADER

            def get_url(self) -> str:
                return self.url

            def get_fields(self) -> list:
                return ['last_analysis_stats','last_dns_records_date','whois','whois_date','creation_date', 'last_update_date','last_modification_date']

        class RequestFactory:
            @staticmethod
            def create_request(indicator: Indicators):
                if indicator.get_type_indicator() == "hash_file":
                    return RequestBuilder.RequestHash(indicator.get_indicator())

                elif indicator.get_type_indicator() == "ip_address":
                    return RequestBuilder.RequestIPAdress(indicator.get_indicator())

                elif indicator.get_type_indicator() == "domain":
                    return RequestBuilder.RequestDomain(indicator.get_indicator())
                else:
                    raise ValueError("Unknown type of Indicators")

class CallAPI:
    def __init__(self, request_obj: list) -> None:
        self.request_obj = request_obj
        self.result_lst: list

    def get_result(self) -> list:
        return self.result_lst

    async def fetch(self, obj: RequestBuilder.RequestVirusTotal, results: list, fields: list):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(obj.get_url(), headers=obj.get_header()) as response:
                    if response.status == 200:
                        data = await response.json()
                        res_attr = data["data"]["attributes"]
                        obj.set_response(res_attr, fields)
                        results.append(obj.get_response())
                    else:
                        print(f"Ошибка: {response.status}")
        except aiohttp.ClientError as e:
            print(f"Client error: {e}")
        except asyncio.TimeoutError:
            print("Запрос занял слишком много времени")

    async def caller(self):
        results = []
        for obj in self.request_obj:
            await self.fetch(obj, results, obj.get_fields())
        self.result_lst = results

class ReportBuilder:
    def __init__(self, result_lst: CallAPI, novalid_lst: list) -> None:
        self.result_lst = result_lst
        self.novalid_lst = novalid_lst


    def build_table(self, res_lst: list):
        for item in res_lst:
           print() 

    def print_table(self, table: Table):
        print(table)

    class Report(Table):
        def __init__(self, title="Проверка IoCs") -> None:
            super().__init__(
                title=title,
                title_style=Style(bold=True, color="green"),
                border_style="blue",
                header_style=Style(bold=True, color="white"),
                highlight=True
            )

    class ReportHash(Report):
        def __init__(self) -> None:
            super().__init__(title="Рeзультаты проверки hash суммы файлов")

        def add_table_column(self) -> None:
            super().add_column("Type tag")
            super().add_column("VT malicious")
            super().add_column("VT suspicious")
            super().add_column("sha256")
            super().add_column("Last submission")
            super().add_column("Last modification")

        def add_table_row(self, data):
            type_tag, malicious, suspicious, sha256, last_submission_date, last_modification_date = data
            super().add_row(type_tag, malicious, suspicious, sha256, last_submission_date, last_modification_date)





if __name__ == "__main__":
    typer.run(main)



