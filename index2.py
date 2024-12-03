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
    """
    if input_file:
        Processor.main(input_file.read())
    elif not sys.stdin.isatty():
        Processor.main(sys.stdin.read())
    else:
        typer.echo("Не предоставлено ни файла, ни данных через stdin.")

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

    @type_indicator.setter
    def type_indicator(self, value: str):
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
            self.type_indicator = "ip_address"

        elif self._validate_hashes(option):
            self.status_valid = True
            self.type_indicator = "hash_file"

        elif self._validate_domain(option):
            self.status_valid = True
            self.type_indicator = "domain"
        else:
            self.type_indicator = "no_valid"

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
        task_respons = Processor.call_api(tasks["valid"])
        # print(res[1].response)
        ReportBuilder(task_respons, tasks["no_valid"])


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

    async def caller(self) -> list:
        results = []
        for task in self.tasks:
            await self.fetch(task, results, task.request.get_fields)
        return results


class ReportBuilder:
    def __init__(self, result_lst: list, novalid_lst: list) -> None:
        self.result_lst = result_lst
        self.novalid_lst = novalid_lst
        self.build_table(self.result_lst)

    def build_table(self, tasks: list):
        hash = self.ReportHash()

        for task in tasks:
            indicator = task.indicator
            if indicator.type_indicator == "hash_file":
                print(task.response)
                hash.add_table_row(task.response)
        print(hash)

    def print_table(self, table: Table):
        print(table)

    class Report(Table):

        _instances = {}

        def __new__(cls, *args, **kwargs):
            if cls not in cls._instances:
                cls._instances[cls] = object.__new__(cls)
            return cls._instances[cls]

        def __init__(self, title="Проверка IoCs") -> None:
            super().__init__(
                title=title,
                title_style=Style(bold=True, color="green"),
                border_style="blue",
                header_style=Style(bold=True, color="white"),
                highlight=True
            )

        def convert_date(self, timestamp):
            value = datetime.datetime.fromtimestamp(timestamp)
            return value.strftime('%d %B %Y')

    class ReportHash(Report):
        def __init__(self) -> None:
            super().__init__(title="Рeзультаты проверки hash суммы файлов")
            self.add_column("Type tag")
            self.add_column("VT malicious")
            self.add_column("VT suspicious")
            self.add_column("sha256")
            self.add_column("Last submission")
            self.add_column("Last modification")

        def add_table_row(self, data):
            try:
                type_tag = data.get('type_tag', '-')
                malicious = data.get('malicious', '-')
                suspicious = data.get('suspicious', '-')
                sha256 = data.get('sha256', '-')
                last_submission_date = self.convert_date(data.get('last_submission_date', '-'))
                last_modification_date = self.convert_date(data.get('last_modification_date', '-'))
                self.add_row(type_tag, str(malicious), str(suspicious), sha256, str(last_submission_date), str(last_modification_date))
            except ValueError as e:
                print(f"Ошибка при добавлении строки: {e}")

if __name__ == "__main__":
    typer.run(main)



