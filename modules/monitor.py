import sys
from collections import Counter

try:
    from __common import get_wlan_iface, flush_msg, exit_program, log_exception
except ModuleNotFoundError:
    try:
        from .__common import get_wlan_iface, flush_msg, exit_program, log_exception
    except ModuleNotFoundError:
        print("'__common.py' not found ...")
        exit(0)

try:
    from scapy.all import sniff as _
    from scapy.all import IP, TCP, ARP, ICMP, Raw, ls
    from scapy.layers import http, inet
except ModuleNotFoundError:
    print("Scapy not installed ...")
    exit(0)

try:
    from netifaces import interfaces
except ModuleNotFoundError:
    print("netifaces not installed ...")
    exit(0)

all_ifaces = interfaces()


class Sniff:
    def __init__(self, iface=None):
        if iface:
            self.iface = iface
        else:
            self.iface = get_wlan_iface()
        self.counter = Counter()
        self.capture = {}

    @property
    def get_captured(self):
        return self.capture

    @property
    def sniff(self):
        if "--sniff-credential" in sys.argv:
            prn_func = self.sniff_credentials
        else:
            prn_func = self.process

        _(iface=self.iface, filter="ip", store=False, prn=prn_func)

    def process(self, packet):
        info = (packet[0][1].src, packet[0][1].dst)
        self.counter.update([info])
        result = "Initiator: {} <==> Receiver: {}".format(
            packet[0][1].src, packet[0][1].dst)
        self.capture[result] = self.counter[info]
        flush_msg(result)

    def sniff_credentials(self, packet):
        if packet.haslayer(http.HTTPRequest):
            flush_msg("HTTP Request from {} | {} ".format(
                packet[http.HTTPRequest].Host, packet[http.HTTPRequest].Path))
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load:
                        flush_msg(
                            "Possible Username or Password Found {}".format(load))


def get_iface_stdin():
    iface = None
    while True:
        try:
            iface = input(
                "Enter the interface from above\n(default='{}'): ".format(get_wlan_iface()))

            if iface in all_ifaces:
                break
            elif isinstance(iface, str) and not iface:
                iface = get_wlan_iface()
                break
            else:
                continue
        except KeyboardInterrupt:
            raise KeyboardInterrupt
        except Exception as e:
            log_exception(e)
            continue
    return iface


def main(name=None):
    print('-' * 60)
    print('-' * 19, ' NETWORK MONITORING ', '-' * 19)

    while True:
        print("-" * 60)
        print("Your network interfaces.")
        print("-" * 60)
        for counter, ifaces in enumerate(all_ifaces):
            print("{}. {}".format((counter+1), ifaces))
        print("-" * 60)
        iface = get_iface_stdin()

        try:
            s = Sniff(iface=iface)
            print("-" * 60)
            if "--sniff-credential" in sys.argv:
                print("Looking for possible username or password ... ")
            else:
                print("Monitoring your network...")
            print("-" * 60)
            s.sniff
            print("")
            print("-" * 60)
            print("Summary")
            print("-" * 60)
            for result, count in s.get_captured.items():
                print("- {} | Count: {}".format(result, count))
            print("-" * 60)
            input("Press enter to continue.")
        except KeyboardInterrupt:
            exit_program(name)
        except Exception as e:
            log_exception(e)
            continue


if __name__ == "__main__":
    main(name=__name__)
