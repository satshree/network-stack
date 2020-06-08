import socket
import subprocess
import sys 
import os
try:
    from netifaces import gateways, AF_INET
except ModuleNotFoundError:
    print("netifaces not installed...")
    exit(0)

def log_exception(exception):
    with open("error.txt", "a") as file:
        file.write("\n")
        file.write("-" * 60)
        file.write("\n")
        file.write(str(exception))
        file.write("\n")
        file.write("-" * 60)

def exit_program():
    print('')
    print('-' * 60)
    print('Closing...')
    print('-' * 60)
    print('')
    exit(0)

def flush_msg(*msg, next_line=True):
    """ Flush out message to terminal. """
    for txt in msg:
        print(txt, end=" ")
        sys.stdout.flush()
    
    if next_line:
        print("")
        sys.stdout.flush()
        
def get_OUI():
    """ Returns list of MAC address and its vendor. """

    current_dir = os.path.dirname(os.path.realpath(__file__))  
    filename = os.path.join(current_dir, 'database.txt')
    with open(filename, 'r', encoding="utf-8") as file:
        contents = file.readlines()
        contents_list = [line.rstrip('\n') for line in contents]

        OUI = {}

        # Filter in such a way: key = MAC address, element = Vendor - 'additional name'(if any).
        for i in contents_list:
            split_list = i.split('\t')
            if len(split_list) == 2:
                OUI[split_list[0]] = split_list[1]
            elif len(split_list) == 3:
                OUI[split_list[0]] = split_list[1] + " - " + split_list[2]

    return OUI

def get_sys_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        sock.connect(('10.255.255.255', 1))
        ip_address = sock.getsockname()[0]
    except:
        try:
            system_hostname = socket.gethostname()
            ip_address = socket.gethostbyname(system_hostname)
        except:
            ip_address = None
    finally:
        return ip_address

def get_sys_gateway():
    return gateways()['default'][AF_INET][0]

    ### OLD WAY
    # if sys.platform == 'win32':
    #     cmd = subprocess.check_output(['ipconfig']).decode('utf-8').split()
    #     gateway = cmd.pop()
    # # elif sys.platform == 'darwin':
    # else:
    #     terminal_command = subprocess.check_output(['route', '-n', 'get', 'default']).decode('utf-8').split()
    #     index = terminal_command.index('gateway:')
    #     gateway = terminal_command[index + 1]

    # octets = gateway.split(".")
    # octets[-1] = "0/24"
    # gateway = ".".join(octets)
    # return gateway

def get_wlan_iface():
    return gateways()['default'][AF_INET][-1]