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


def set_interfaces():
    ifaces = interfaces()
    if sys.platform == "win32":
        import winreg

        reg = winreg.ConnectRegistry(None, winreg.HKEY_LOCAL_MACHINE)
        try:
            reg_key = winreg.OpenKey(
                reg, r'SYSTEM\\CurrentControlSet\\Control\\Network\\{4d36e972-e325-11ce-bfc1-08002be10318}')
        except:
            try:
                reg_key = winreg.OpenKey(
                    reg, r'SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}')
            except:
                print("Cannot get interfaces.")
                if __name__ == "__main__":
                    exit(0)
                else:
                    raise KeyboardInterrupt

        for i in range(len(ifaces)):
            iface_guid = ifaces[i]
            try:
                reg_subkey = winreg.OpenKey(
                    reg_key, iface_guid + r'\\Connection')
                iface_name = winreg.QueryValueEx(reg_subkey, 'Name')[0]
                ifaces[i] = iface_name
            except FileNotFoundError:
                pass
        
    return ifaces

ALL_IFACES = set_interfaces()
WLAN = get_wlan_iface()


class Sniff:
    def __init__(self, iface=None):
        if iface:
            self.iface = iface
        else:
            self.iface = WLAN
        self.counter = Counter()
        self.capture = {}

    @property
    def get_captured(self):
        return self.capture

    def sniff(self):
        prn_func = self.process

        _(iface=self.iface, filter="ip", store=False, prn=prn_func)

    def process(self, packet):
        info = (packet[0][1].src, packet[0][1].dst)
        self.counter.update([info])
        result = "Initiator: {} <==> Receiver: {}".format(
            packet[0][1].src, packet[0][1].dst)
        self.capture[result] = self.counter[info]
        flush_msg(result)


def get_iface_stdin():
    iface = None
    while True:
        try:
            iface = input(
                "Enter the interface from above\n(default='{}'): ".format(WLAN))

            if iface in ALL_IFACES:
                break
            elif isinstance(iface, str) and not iface:
                iface = WLAN
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
    print('-' * 60)
    print("-" * 10, "MONITOR TRAFFIC INITIATOR AND RECEIVER", "-" * 10)

    while True:
        print("-" * 60)
        print("Your network interfaces,")
        # print("\n")
        for counter, ifaces in enumerate(ALL_IFACES):
            print("{}. {}".format((counter+1), ifaces))
        print("-" * 60)

        try:
            iface = get_iface_stdin()
            s = Sniff(iface=iface)

            print("-" * 60)
            print("Monitoring your network...")
            print("-" * 60)

            s.sniff()

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
