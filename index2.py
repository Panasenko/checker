#!/bin/python3

import typer
import sys

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

if __name__ == "__main__":
    typer.run(main)
