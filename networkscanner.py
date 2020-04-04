import sys
import socket
import time
try:
    from scapy.all import srp, ARP, Ether
except ModuleNotFoundError:
    print("Scapy not installed ...")
    exit(0)

try:
    from common.common import exit_program, get_OUI, get_sys_gateway#, get_sys_ip
except ModuleNotFoundError:
    print("'common' folder and its components not found ...")
    exit(0)

def flush_msg(*msg, next_line=True):
    """ Flush out message to terminal. """
    for txt in msg:
        print(txt, end=" ")
        sys.stdout.flush()
    
    if next_line:
        print("")
        sys.stdout.flush()

class ScanHost:
    def __init__(self, network=None, attempts=5):
        if network:
            if self.validate_network_address(network):
                self.ip = network
            else:
                raise Exception("Invalid Network Address.")
        else:
            self.ip = get_sys_gateway()
        self.attempts = attempts
        self.hosts = {}
    
    @property
    def get_hosts(self):
        return self.hosts
    
    @property
    def total_hosts(self):
        return len(self.hosts.keys())
    
    def validate_network_address(self, ip): 
        """ Validate Network Address. """
        if ("." in ip) and (len(ip) > 11) and (ip[-5:-2] == ".0/"):
            return True
        else:
            return False

    def scan(self, verbose=False):
        """ Scan the network. """

        if verbose:
            flush_msg("Creating an ARP Packet...")
        arp = ARP(pdst=self.ip)

        if verbose:
            flush_msg("Creating broadcast frame...")
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")

        if verbose:
            flush_msg("Stacking ARP packet and broadcast frame...")
        arp_broadcast = broadcast/arp

        if verbose:
            flush_msg("-" * 60)

        for attempt in range(self.attempts):
            if verbose:
                flush_msg("\rScanning network {} | Attempt: {} of {}...".format(self.ip, (attempt + 1), self.attempts), next_line=False)
            answered = srp(arp_broadcast, timeout=2, verbose=False)[0]

            for element in answered:
                self.hosts[element[1].psrc] = {'MAC': element[1].hwsrc.upper()}
        
        if verbose:
            flush_msg("")

        return self.hosts
    
    def vendor(self):
        """ Identify vendor of online caught hosts. """

        oui = get_OUI()

        for host in self.hosts.keys():
            mac = self.hosts[host]['MAC']
            self.hosts[host]['Vendor'] = oui.get(mac[:8])
    
    def hostname(self):
        """ Set Hostname of the device. """

        for ip in self.hosts.keys():
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = None
            self.hosts[ip]['Hostname'] = hostname

    def os(self):
        """ Fingerprint OS by nmap. """
        pass

def main():
    print('-' * 60)
    print('-' * 20 , ' NETWORK SCANNING ', '-' * 20)

    while True:
        try:
            print("-" * 60)
            network = input("Enter Network Address\n(leaving empty will target your gateway address): ")

            print("-" * 60)
            attempts = input("Enter Total Network Scanning Attempts(default=5): ")
            
            if attempts:
                attempts = int(attempts)
            else:
                attempts = 5

            scan = ScanHost(network=network, attempts=attempts)

            start = time.time()
            print("-" * 60)
            print("STATUS")
            print("-" * 60)
            scan.scan(verbose=True)

            print("-" * 60)
            print("Identifying Vendor...")
            scan.vendor()

            print("-" * 60)
            print("Identifying Hostnames...")
            scan.hostname()

            # print("-" * 60)
            # print("Identifying Operating System...")
            # scan.hostname()

            end = time.time()

            print("-" * 60)
            print("Results...")
            for host, info in scan.get_hosts.items():
                print("-" * 60)
                print("HOST:", host)
                print("MAC Address:", info["MAC"])
                print("Vendor:", info["Vendor"])
                print("Hostname:", info["Hostname"])
                # print("OS:", info["OS"])
            
            print("-" * 60)
            print("Total Hosts:", len(scan.get_hosts.keys()))
            print("-" * 60)
            print("Total Time Taken:", int(end-start), "seconds")
            # print("-" * 60)
        except KeyboardInterrupt:
            exit_program()
        except Exception as e:
            print("Exception:", str(e))

if __name__ == "__main__":
    main()