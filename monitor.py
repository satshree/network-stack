from collections import Counter

try:    
    from common.common import get_wlan_iface, flush_msg, exit_program, log_exception
except ModuleNotFoundError:
    print("'common' folder and its components not found ...")
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
        _(iface=self.iface, filter="ip", store=False, prn=self.process)
    
    def process(self, packet):
        info = (packet[0][1].src, packet[0][1].dst)
        self.counter.update([info])
        result = "Initiator: {} <==> Receiver: {}".format(packet[0][1].src, packet[0][1].dst)
        self.capture[result] = self.counter[info]
        flush_msg(result)

def get_iface_stdin():
    iface = None
    while True:
        try:
            iface = input("Enter the interface from above\n(default='{}'): ".format(get_wlan_iface()))

            if iface in all_ifaces:
                break
            elif isinstance(iface, str) and not iface:
                iface = get_wlan_iface()
                break
            else:
                continue
        except KeyboardInterrupt:
            exit_program()
        except Exception as e:
            log_exception(e)
            continue
    return iface


def main():   
    print('-' * 60)
    print('-' * 19 , ' NETWORK MONITORING ', '-' * 19)

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
            exit_program()
        except Exception as e:
            log_exception(e)
            continue

if __name__ == "__main__":
    main()