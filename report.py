
class Report(object):
    def __init__(self):
        self.table = PrettyTable()
        self.table.field_names = ["Parameter", "Value"]
        self.view = ["geo", "ip", "score", "country"]
        self.report = []

    def generet_report(self, data):
        for key in data:
            key_data = data[key]

            if key in self.view:
                if type(key_data) is str or type(key_data) is int:
                    self.report.append([key, key_data])

                if type(key_data) is dict:
                    for i in key_data:
                        if i in self.view:
                            self.report.append([i, key_data[i]])

        return self.report

    def draw_report(self, data):
        self.table.add_rows(data)
        print(self.table)
