#!/bin/python3

# import vt
#
# client = vt.Client("d6c516e8c532da2c8d10062de712d320f4f0b6da7de92b451a358d6617540f0a")
# file = client.get_object("/files/44d88612fea8a8f36de82e1278abb02f")
# print(file.size)
# client.close()

import optparse

class Main(object):
    def __init__(self):
        self.option = Options()
        self.checkFile = CheckFile()
        self.start()

    def start(self):
        file_path = self.option.opt_parser()
        ioc_list = self.checkFile.readFile(file_path)
        self.checkFile.checkList(ioc_list)


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

class CheckFile(object):
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

    def checkList(self, ioc_list):
        while ioc_list:
            element = ioc_list.pop(0)
            print(element)    

        print(ioc_list)


if __name__ == "__main__":
    main = Main()

