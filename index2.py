#!/bin/python3

import typer
import sys
import re

def main(input_file: typer.FileText = typer.Argument(None, help="Входной файл (опционально)")):
    if input_file:
        scheduler(input_file.read())
    elif not sys.stdin.isatty():
        scheduler(sys.stdin.read())
    else:
        typer.echo("Не предоставлено ни файла, ни данных через stdin.")

def scheduler(content: str):
    for line in content.splitlines():
        ind = Indicators(line)
        print(ind.get_type_indicator())

class Indicators:
    ip_pattern = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    hash_pattern = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    def __init__(self, indicator: str):
        self.indicator = indicator
        self._status_valid = False
        self._type_indicator: str
        self._data_virustotal: list

        self.valid_indicators(self.indicator)

    def get_status_valid(self) -> bool:
        return self._status_valid

    def set_status_valid(self, value: bool):
        self._statusValid = value

    def get_type_indicator(self) -> str:
        return self._type_indicator

    def set_type_indicator(self, value: str):
        self._type_indicator = value

    def _validate_ip_adress(self, value) -> bool:
        return bool(re.fullmatch(self.ip_pattern, value))

    def _validate_hashes(self, value) -> bool:
        return bool(re.fullmatch(self.hash_pattern, value))

    def _validate_domain(self, value) -> bool:
        return bool(re.fullmatch(self.domain_pattern, value))

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

if __name__ == "__main__":
    typer.run(main)
