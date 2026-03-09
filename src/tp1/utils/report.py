from tp1.utils.capture import Capture
import pygal


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "TITRE DU RAPPORT"
        self.summary = summary
        self.array = ""
        self.graph = ""

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        content = ""
        content += self.title
        content += self.summary
        content += self.array
        content += self.graph

        return content

    def save(self, filename: str) -> None:
        """
        Save report in a file
        :param filename:
        :return:
        """
        final_content = self.concat_report()
        with open(self.filename, "w") as report:
            report.write(final_content)

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        if param == "graph":

            stats = self.capture.sort_network_protocols()

            chart = pygal.Bar()
            chart.title = "Network Traffic by IP"

            chart.x_labels = list(stats.keys())

            protocols = set()
            for data in stats.values():
                protocols.update(data["protocols"].keys())

            for proto in protocols:
                values = []

                for ip in stats:
                    values.append(stats[ip]["protocols"].get(proto, 0))

                chart.add(proto, values)

            graph = chart.render(is_unicode=True)
            chart.render_to_file("network_graph.svg")

            self.graph = "\n===== Graph =====\n\n" + graph
        elif param == "array":

            stats = self.capture.sort_network_protocols()

            array = "\n===== Network Statistics Table =====\n\n"
            array += "IP\t\tMAC\t\tProtocol\tCount\n"

            for ip, data in stats.items():
                mac = data["mac"]

                for proto, count in data["protocols"].items():
                    array += f"{ip}\t{mac}\t{proto}\t{count}\n"

            self.array = array
