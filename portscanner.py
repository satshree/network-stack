import sys
import socket

try:
    from scapy.all import IP, TCP, sr1
except ModuleNotFoundError:
    pass

try:
    from common.common import exit_program, log_exception
except ModuleNotFoundError:
    print("'common' folder and its components not found ...")
    exit(0)

class ScanPort:
    def __init__(self, host, port=[]):
        self.host = host
        if port:
            self.port = port
        else:
            self.port = self.known_ports
        
        self.open_ports=[]
    
    @property
    def known_ports(self):
        return [5,7,18,20,21,22,23,25,29,37,42,43,49,53,69,70,79,80,103,108,109,110,\
            115,118,119,137,139,143,150,156,161,179,190,194,197,389,396,443,444,\
            445,458,546,547,563,569,1080]
    
    @property
    def get_open_ports(self):
        open_ports = []
        for port in self.open_ports:
            for p in port.keys():
                open_ports.append(p)
        return open_ports

    def connect_scan(self, verbose=False):
        """ Perform TCP Connect Scan. """

        for port in self.port:
            if verbose:
                print("\rScanning port {}...".format(port), end="")
                sys.stdout.flush()
            try:
                # TCP Socket Connection.
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                # Two Second Connection Time.
                s.settimeout(2)

                # Complete Three Way Handshake
                s.connect((self.host, int(port)))

                # Get Port Service Name
                try:
                    port_desc = socket.getservbyport(int(port)).upper()
                except:
                    port_desc = "Unknown"
                    
                self.open_ports.append({
                    port:port_desc
                })

                s.close()
            except KeyboardInterrupt:
                exit_program()
            except:
                # If Connection Fails
                pass

        if verbose:
            print("")
            sys.stdout.flush()

        return self.open_ports
    
    def stealth_scan(self, verbose=False):
        """ Perform SYN Scan. """

        try:
            # IP Packet.
            ip = IP(dst=self.host)

            for port in self.port:
                if verbose:
                    print("\rScanning port {}...".format(port), end="")
                    sys.stdout.flush()                    

                # TCP Packet.
                tcp = TCP(dport=int(port), flags="S", seq=int(port))

                # Stack IP and TCP packets to send.
                packet = ip/tcp

                # Connect to given port to check for open port.
                reply = sr1(packet, verbose=False, timeout=2)  # sr1 sends packets at Layer 3.

                if hasattr(reply, 'seq'):
                    if reply.seq:
                        if reply.seq > 0:
                            # If the port is open.
                            try:
                                port_desc = socket.getservbyport(int(port)).upper()
                            except:
                                port_desc = "Unknown"

                            self.open_ports.append({
                                port: port_desc
                            })
        except ModuleNotFoundError:
            raise ModuleNotFoundError
        except KeyboardInterrupt:
            exit_program()
        except Exception as e:
            log_exception(e)
        else:
            if verbose:
                print("")
                sys.stdout.flush()
            return self.open_ports

def main():
    print('-' * 60)
    print('-' * 21 , ' PORT  SCANNING ', '-' * 21)

    if "-stealth" not in sys.argv:
        print('-' * 60)
        print("Run portscanner with flag '-stealth' to perform stealth scan.")

    while True:
        try:
            print('-' * 60)
            host = input('Enter hostname: ')
            try:
                ip=socket.gethostbyname(host)
                print('>>> Hostname resolved into', ip)
            except:
                print('>>> Cannot resolve the hostname.')
                continue

            print('-' * 60)
            port = input('Enter port to scan: ')
            if port:
                port = port.split(",")
            else:
                port=[]
            scan = ScanPort(ip, port=port)
            print("-" * 60)
            try:
                if "-stealth" in sys.argv:
                    print("Performing stealth scan ...")
                    print("-" * 60)
                    open_ports = scan.stealth_scan(verbose=True)
                else:
                    print("Performing connect scan ...")
                    print("-" * 60)
                    open_ports = scan.connect_scan(verbose=True)
            except ModuleNotFoundError:
                print("Scapy not installed, performing connect scan ...")
                print("-" * 60)
                open_ports = scan.connect_scan(verbose=True)
            except KeyboardInterrupt:
                # raise KeyboardInterrupt
                exit_program()
        except KeyboardInterrupt:
            exit_program()
        # except:
        #     print('')
        #     print('-' * 60)
        #     print('Try Again...')
        else:
            print("-" * 60)
            if open_ports:
                print("PORT\t|\tDESCRIPTION")
                print("-" * 60)
                for ports in open_ports:
                    for port, desc in ports.items():
                        print("{}\t|\t{}".format(port, desc))
            else:
                print("No Open Ports Found...")

if __name__ == "__main__":
    main()