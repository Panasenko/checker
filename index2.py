#!/bin/python3

import typer
import sys
import re

def main(input_file: typer.FileText = typer.Argument(None, help="Входной файл (опционально)")):
    if input_file:
        # Чтение данных из файла
        content = input_file.read()
        typer.echo(f"Данные, считанные из файла:\n{content}")
    elif not sys.stdin.isatty():
        # Чтение данных из stdin
        content = sys.stdin.read()
        typer.echo(f"Данные, считанные через stdin:\n{content}")
    else:
        typer.echo("Не предоставлено ни файла, ни данных через stdin.")

 

class Indicators:

    ip_pattern = r'^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'
    hash_pattern = r"\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'

    def __init__(self, indicator: str):
        self.indicator = indicator
        self._statusValid = False
        self._typeIndicator: str

    def get_statusValid(self) -> bool:
        return self._statusValid

    def set_statusValid(self, value: bool):
        self._width = value

    def get_typeIndicator(self) -> str:
        return self._typeIndicator

    def set_typeIndicator(self, value: str):
        self._typeIndicator = value

    def _validateIpAdress(self, value):
        return bool(re.fullmatch(self.ip_pattern, value))

    def _validateHashes(self, value):
        return bool(re.fullmatch(self.hash_pattern, value))

    def _validateDomain(self, value):
        return bool(re.fullmatch(self.domain_pattern, value))

    def validIndicators(self, option):
        if self.validateIpAdress(option):
            self.set_statusValid(True)
            self.set_typeIndicator("IP_address")
        elif self.validateHashes(option):
            self.set_statusValid(True)
            self.set_typeIndicator("hash_file")
        elif self.validateDomain(option):
            self.set_statusValid(True)
            self.set_typeIndicator("domain")
        else:
            return response






if __name__ == "__main__":
    typer.run(main)
