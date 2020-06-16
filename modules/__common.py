import socket
import subprocess
import sys 
import os
try:
    from netifaces import gateways, AF_INET, ifaddresses
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

def exit_program(name):
    if name=="__main__":
        print('')
        print('-' * 60)
        print('Closing...')
        print('-' * 60)
        print('')
        exit(0)
    else:
        raise KeyboardInterrupt

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
    return ifaddresses(get_wlan_iface())[AF_INET][0]['addr']

def get_sys_gateway():
    return gateways()['default'][AF_INET][0]

def get_wlan_iface():
    return gateways()['default'][AF_INET][-1]