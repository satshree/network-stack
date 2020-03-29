import sys
import socket
from common.common import exit_program
try:
    from portscanner import ScanPort
except ModuleNotFoundError:
    print("'portscanner.py' not found!")
    exit(0)

class GrabBanner:
    def __init__(self, host, ports=None):
        self.host=host
        if ports:
            self.ports=ports
        else:
            scan_port = ScanPort(self.host)

            print("-" * 60)
            # Get Open Ports
            try:
                print("No ports defined, performing stealth scan...")
                print("-" * 60)
                scan_port.stealth_scan(verbose=True)
            except ModuleNotFoundError:
                print("Scapy not installed, performing connect scan ...")
                print("-" * 60)
                scan_port.connect_scan(verbose=True)

            self.ports = scan_port.get_open_ports
        self.banners={}
    
    @property
    def get_banners(self):
        return self.banners

    def grab(self, payload=None, verbose=False):
        """ Banner Grabbing. """

        for port in self.ports:
            if verbose:
                print('\rGrabbing banner for port {}.'.format(port), end="")
                sys.stdout.flush()

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((host, port))

                if not payload:
                    # Payload for banner grabbing
                    data0 = "GET / HTTP/1.1\r\nhost:"
                    data1 = str(socket.gethostbyname(socket.gethostname()))
                    data2 = "\r\nConnection: keep alive\r\n\r\n"
                    payload = data0 + data1 + data2

                s.send(payload.encode())

                s.close()
                self.banners[port] = s.recv(1024).decode('utf-8')
            except:
                pass
        
        if verbose:
            print("")
            sys.stdout.flush()

        return self.banners

def main():
    print('-' * 60)
    print('-' * 20 , ' BANNER  GRABBING ', '-' * 20)

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
            port = input('Enter ports to grab banner: ')
            if port:
                port = port.split(",")
            else:
                port=[]
            banner = GrabBanner(ip, ports=port)

            banners = banner.grab(verbose=True)
        except KeyboardInterrupt:
            exit_program()
        # except:
        #     print('')
        #     print('-' * 60)
        #     print('Try Again...')
        else:
            if banners:
                print("-" * 60)
                for port, banner in banners.items():
                    print("Banner for port {}.".format(port))
                    print("-" * 60)
                    print(banner)
                    print("-" * 60)
            else:
                print("-" * 60)
                print("No Banners Caught For Given Ports.")


if __name__ == '__main__':
    main()