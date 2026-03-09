from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
import netifaces
import scapy
from scapy.all import sniff


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""

    @staticmethod
    def is_interface_up_non_virtual(iface: str) -> bool:
        EXCLUDED_PREFIXES = ("lo", "vbox", "virbr", "docker", "br-", "vmnet", "tun", "tap")

        if iface == "lo" or iface.startswith(EXCLUDED_PREFIXES):
            return False

        try:
            addrs = netifaces.ifaddresses(iface)
        except ValueError:
            return False

        return netifaces.AF_INET in addrs

    @staticmethod
    def analyse_paquet(packet):
        print(packet)

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        if_list = netifaces.interfaces()
        up_interfaces = [
            iface for iface in if_list
            if self.is_interface_up_non_virtual(iface)
        ]

        logger.info(f"Interfaces up: {up_interfaces}")

        if up_interfaces:
            interface = up_interfaces[0]
        else:
            interface = self.interface

        logger.info(f"Capture traffic from interface {interface}")
        self.packets= sniff(iface=interface, count=300, prn=self.analyse_paquet, store=True)
        logger.info(f"{self.packets}")

    def sort_network_protocols(self) -> dict:
        """
        Organise les statistiques par IP source pour identifier
        qui fait quoi sur le réseau.
        """
        if not self.packets:
            return {}

        stats_by_ip = {}

        for packet in self.packets:
            # On cherche l'IP source (couche IP ou IPv6)
            src_ip = "Unknown"
            if packet.haslayer('IP'):
                src_ip = packet['IP'].src
            elif packet.haslayer('IPv6'):
                src_ip = packet['IPv6'].src
            elif packet.haslayer('ARP'):
                src_ip = packet['ARP'].psrc
            src_mac = "Unknown"
            if packet.haslayer('Ether'):
                src_mac = packet['Ether'].src

            proto = packet.lastlayer().name

            if src_ip not in stats_by_ip:
                stats_by_ip[src_ip] = {
                    "mac": src_mac,
                    "protocols": {}
                }

            protocols = stats_by_ip[src_ip]["protocols"]
            protocols[proto] = protocols.get(proto, 0) + 1

        #logger.info(f"Stats groupées par IP : {stats_by_ip}")
        return stats_by_ip

    def get_all_protocols(self) -> str:

        if not self.packets:
            return "No packets captured"

        protocol_count = {}

        for packet in self.packets:

            protocol = packet.lastlayer().name

            if protocol not in protocol_count:
                protocol_count[protocol] = 0

            protocol_count[protocol] += 1

        result = ""

        for proto, count in protocol_count.items():
            result += f"{proto}: {count}\n"

        logger.info(f"Sorting protocols: {result}")
        return result

    def analyse(self, protocols: str) -> None:

        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()

        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        for ip, data in sort.items():
            mac = data["mac"]

            for typ, value in data["protocols"].items():
                #print(f"{ip} ({mac}) : {typ} : {value}")

                # Détection d'activité suspecte
                if value > 100:
                    logger.warning(
                        f"Activité suspecte détectée : "
                        f"{value} paquets {typ} envoyés par {ip} ({mac}). "
                        f"Possible tentative d'attaque réseau."
                    )

                    # Détection ARP Spoofing
                    if typ == "ARP":
                        logger.warning(
                            f"Possible ARP Spoofing détecté depuis {ip} ({mac})"
                        )

                    # Détection flood TCP
                    if typ == "TCP":
                        logger.warning(
                            f"Possible TCP flood ou scan réseau depuis {ip} ({mac})"
                        )

                    # Détection flood UDP
                    if typ == "UDP":
                        logger.warning(
                            f"Possible UDP flood depuis {ip} ({mac})"
                        )
                else :
                    logger.info(f"Le traffic venant de l'IP/MAC : {ip}/{mac} semble légitime RAS")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """

        sort = self.sort_network_protocols()

        summary = "===== Network Analysis Summary =====\n\n"

        if not sort:
            return "No packets captured.\n"

        for ip, data in sort.items():

            mac = data["mac"]

            summary += f"Source : {ip} ({mac})\n"

            for proto, count in data["protocols"].items():
                summary += f"   - {proto} : {count} packets\n"

            summary += "\n"

        summary += "Analysis completed.\n"

        return summary
