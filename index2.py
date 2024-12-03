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

from typing import Union
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
        Processor.main(input_file.read())
    elif not sys.stdin.isatty():
        Processor.main(sys.stdin.read())
    else:
        typer.echo("Не предоставлено ни файла, ни данных через stdin.")




    # if input_file:
    #     scheduler(input_file.read())
    # elif not sys.stdin.isatty():
    #     scheduler(sys.stdin.read())
    # else:
    #     typer.echo("Не предоставлено ни файла, ни данных через stdin.")

# def scheduler(content: str):
#     array_requests_objects = []
#     array_novalid_objects = []
#
#     for line in content.splitlines():
#
#         indicator_object = Indicators(line)
#
#         if indicator_object.status_valid:
#             request = RequestBuilder(indicator_object)
#             request_object = request.get_object()
#
#             if request_object is not None:
#                 array_requests_objects.append(request_object)
#         else:
#             array_novalid_objects.append(indicator_object)
#
#     call_api = CallAPI(array_requests_objects)
#     asyncio.run(call_api.caller())
#
#     print(call_api.__dict__)
#

class Indicators:
    IP_PATTERN = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    HASH_PATTERN = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
    DOMAIN_PATTERN = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    def __init__(self, indicator: str) -> None:
        self.indicator = indicator
        self._status_valid = False
        self._type_indicator: str
        self.valid_indicators(self.indicator)

    """
    Обьевление геттеров и сеттеров
    """

    @property
    def get_indicator(self) -> str:
        return self.indicator

    @property
    def status_valid(self) -> bool:
        return self._status_valid

    @status_valid.setter
    def status_valid(self, value: bool):
        self._status_valid = value

    @property
    def type_indicator(self) -> str:
        return self._type_indicator

    def set_type_indicator(self, value: str):
        self._type_indicator = value

    """
    Блок валидаций индикаторов компрометации
    """

    def _validate_ip_adress(self, value) -> bool:
        return bool(re.fullmatch(self.IP_PATTERN, value))

    def _validate_hashes(self, value) -> bool:
        return bool(re.fullmatch(self.HASH_PATTERN, value))

    def _validate_domain(self, value) -> bool:
        return bool(re.fullmatch(self.DOMAIN_PATTERN, value))

    def valid_indicators(self, option: str):
        if self._validate_ip_adress(option):
            self.status_valid = True
            self.set_type_indicator("ip_address")

        elif self._validate_hashes(option):
            self.status_valid = True
            self.set_type_indicator("hash_file")

        elif self._validate_domain(option):
            self.status_valid = True
            self.set_type_indicator("domain")
        else:
            self.set_type_indicator("no_valid")

"""
Создание запроса в сервис ViruseTotal
"""
class RequestBuilder:
        def __init__(self, indicator: Indicators) -> None:
            self.indicator = indicator

        class RequestVirusTotal(ABC):
            BASE_URL_VT = os.getenv("BASE_URL_VT")
            HEADER = {'x-apikey': os.getenv("API_KEY"), 'accept': 'application/json'}
            
            def __init__(self, indicator: str) -> None:
                self.indicator = indicator

            @property
            @abstractmethod
            def get_url(self) -> str:
                pass
            
            @property
            @abstractmethod
            def get_header(self) -> dict:
                pass

            @property
            @abstractmethod
            def get_fields(self) -> list:
                pass

        class RequestHash(RequestVirusTotal):
            def __init__(self, indicator: str) -> None:
                super().__init__(indicator) 
                self.url = f"{super().BASE_URL_VT}files/{self.indicator}" 

            @property
            def get_header(self) -> dict:
                return super().HEADER

            @property
            def get_url(self) -> str:
                return self.url
        
            @property
            def get_fields(self) -> list:
                return ['last_analysis_stats', 'sha256', 'md5','sha1','type_tag','last_submission_date','last_modification_date']

        class RequestIPAdress(RequestVirusTotal):
            def __init__(self, indicator: str) -> None:
                super().__init__(indicator)
                self.url = f"{super().BASE_URL_VT}ip_addresses/{self.indicator}"

            @property
            def get_header (self) -> dict:
                return super().HEADER

            @property
            def get_url(self) -> str:
                return self.url

            @property
            def get_fields(self) -> list:
                return ['last_analysis_stats', 'country', 'whois', 'whois_date','last_analysis_date','last_modification_date']

        class RequestDomain(RequestVirusTotal):
            def __init__(self, indicator: str) -> None:
                super().__init__(indicator)
                self.url = f"{super().BASE_URL_VT}domains/{self.indicator}"

            @property
            def get_header(self) -> dict:
                return super().HEADER

            @property
            def get_url(self) -> str:
                return self.url

            @property
            def get_fields(self) -> list:
                return ['last_analysis_stats','last_dns_records_date','whois','whois_date','creation_date', 'last_update_date','last_modification_date']

        def get_object(self) -> Union[RequestHash, RequestIPAdress, RequestDomain, None]:
            try:
                request_object = self.RequestFactory.create_request(self.indicator)
            except ValueError as e:
                logging.error(f"Создание обьекта класса RequestFactory заверщилось ошибкой: {e}. Обработка индикатора {self.indicator.get_indicator}")
                return None
            else:
                return request_object

        class RequestFactory:
            @staticmethod
            def create_request(indicator: Indicators):
                if indicator.type_indicator == "hash_file":
                    return RequestBuilder.RequestHash(indicator.get_indicator)

                elif indicator.type_indicator == "ip_address":
                    return RequestBuilder.RequestIPAdress(indicator.get_indicator)

                elif indicator.type_indicator == "domain":
                    return RequestBuilder.RequestDomain(indicator.get_indicator)
                else:
                    raise ValueError("Unknown type of Indicators")

class Task:
    def __init__(self, ioc) -> None:
        self._ioc = ioc
        self._indicator: Indicators
        self._request: Union[RequestBuilder.RequestHash, RequestBuilder.RequestIPAdress, RequestBuilder.RequestDomain, None]
        self._response: dict
    
    @property
    def indicator(self) -> Indicators:
        return self._indicator

    @indicator.setter
    def indicator(self, indicator: Indicators) -> None:
        self._indicator = indicator

    @property
    def request(self) -> Union[RequestBuilder.RequestHash, RequestBuilder.RequestIPAdress, RequestBuilder.RequestDomain, None]:
        return self._request

    @request.setter
    def request(self, request: Union[RequestBuilder.RequestHash, RequestBuilder.RequestIPAdress, RequestBuilder.RequestDomain, None] ) -> None:
        self._request = request

    @property
    def response(self) -> dict:
        return self._response

    @response.setter
    def response(self, response: dict) -> None:
        self._response = response

class Processor:
    @staticmethod
    def main(content: str):
        tasks = Processor.conveyor(content)
        res = Processor.call_api(tasks["valid"])
        print(res[1].response)

    @staticmethod
    def conveyor(content: str) -> dict:
        valid_objects = []
        novalid_objects = []

        for line in content.splitlines():
            """Создание обьекта задачи"""
            task = Task(list)

            """Валидация индикаторов компрометации"""
            task.indicator = Indicators(line)

            if task.indicator.status_valid:
                task.request = RequestBuilder(task.indicator).get_object()
                valid_objects.append(task)
            else:
                novalid_objects.append(task)
        return {
            "valid": valid_objects,
            "no_valid": novalid_objects
        }
                
    @staticmethod
    def call_api(valid_tasks: list):
        call_api = CallAPI(valid_tasks)
        return asyncio.run(call_api.caller())

class CallAPI:
    def __init__(self, tasks: list) -> None:
        self.tasks = tasks

    async def fetch(self, task: Task, results: list, fields: list):
        try:
            async with aiohttp.ClientSession() as session:
                if task.request:
                    async with session.get(task.request.get_url, headers=task.request.get_header) as response:
                        if response.status == 200:
                            data = await response.json()
                            res_attr = data["data"]["attributes"]
                            task.response = self.set_response(res_attr, fields)
                            results.append(task)
                        else:
                            print(f"Ошибка: {response.status}")
                else:
                    print("В обьекте Task отсутствует сформированный обьект зазпрос")
        except aiohttp.ClientError as e:
            print(f"Client error: {e}")
        except asyncio.TimeoutError:
            print("Запрос занял слишком много времени")

    def set_response(self, response: dict, fields: list) -> dict:
        dict_response = {}
        if bool(response and fields):
            for item in fields:
                if item == "last_analysis_stats":
                    dict_response.update(response.pop('last_analysis_stats'))
                else:
                    dict_response[item] = response[item]
        return dict_response

    async def caller(self):
        results = []
        for task in self.tasks:
            await self.fetch(task, results, task.request.get_fields)
        return results


class ReportBuilder:
    def __init__(self, result_lst: CallAPI, novalid_lst: list) -> None:
        self.result_lst = result_lst
        self.novalid_lst = novalid_lst

    def convert_date(self, timestamp):
        value = datetime.datetime.fromtimestamp(timestamp)
        return value.strftime('%d %B %Y')

    # def build_table(self, res_lst: list):
    #     for item in res_lst:
    #        print() 

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



