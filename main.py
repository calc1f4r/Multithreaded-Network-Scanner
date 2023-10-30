from datetime import datetime
import argparse
import socket
import re
import concurrent.futures
from queue import Queue
import scapy.all as scapy
from  termcolor import colored
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target URL or IP address")
    parser.add_argument(
        "-arp",
        dest="arp",
        help="Use this for ARP ping!",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "-pT",
        dest="tcpPortScan",
        help="TCP Port Scan",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "-pU",
        dest="udpPortScan",
        help="UDP Port Scan",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "-p",
        "--ports",
        dest="ports",
        help="Port range to scan, default is 1-65535 (all ports)",
        required=False,
        action="store",
        default="1-65535",
    )
    parser.add_argument(
        "-t",
        "--threads",
        dest="threads",
        help="Threads for speed, default is 100",
        required=False,
        action="store",
        default=100,
        type=int,
    )
    return parser.parse_args()

def arp_ping(ip):
    if not re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$", ip):
        print(colored("[-] Please provide a valid IP address range for ARP ping!",'red',attrs=['bold']))
        exit(1)

    try:
        arp_request_frame = scapy.ARP(pdst=ip)
        ether_broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast_arp_packet = ether_broadcast_frame / arp_request_frame
        active_clients = scapy.srp(
        broadcast_arp_packet, timeout=3, verbose=False)[0]
        
        for _, reply in active_clients:
            print(f"[+]\t{reply.psrc}\t{reply.hwsrc}")
    except Exception as err:
        print(colored(f"[-] Error occurred! Reason: {err}",'red',attrs=['dark']))

def port_scan(port, host, scan_type):
    try:
        if scan_type == "T":
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(1)
            client.connect((host, port))
            client.close()
            print(f"[*]\t{port}\tOpen")
        elif scan_type == "U":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            client.connect((host, port))
            print(f"[*]\t{port}\tOpen")
            sock.close()
    except KeyboardInterrupt:
        print("You pressed Ctrl+C")
        exit(1)
    except:
        pass

def scan_thread(host, scan_type, port_queue):
    while True:
        try:
            port = port_queue.get_nowait()
            port_scan(port, host, scan_type)
            port_queue.task_done()
        except queue.Empty:
            break

def main():
    args = get_args()
    host = args.target
    start_port, end_port = map(int, args.ports.split("-"))
    scan_type = ""
    port_queue = Queue()
    print(colored("-"*65, 'cyan', attrs=['dark']))
    print(colored(
            f"\tNetwork scanner starting at {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", 'cyan', attrs=['dark']))
    print(colored("-"*65, 'cyan', attrs=['dark']))
    if args.arp:
        print(colored("-"*50,'light_red'))
        print(colored("\tARP Ping Scan Results",'light_red'))
        print(colored("-"*50,'light_red'))
        print(colored("="*30,'black'))
        print(colored("\tPort\tState",'black',attrs=['bold']))
        print(colored("="*30,'black'))
        arp_ping(host)

    if ((args.tcpPortScan)or(args.udpPortScan)):
        print(colored("-"*50,'light_red'))
        if args.tcpPortScan:
            print(colored("\tTCP Port Scan Results",'light_red'))
            scan_type="T"
        elif (args.udpPortScan):
            print(colored("\tUDP Port Scan Results",'light_red'))
            scan_type="U"
        print(colored("-"*50,'light_red'))
        print()
        print(colored("="*30,'dark_grey'))
        print(colored("\tPort\tState",'dark_grey',attrs=['bold']))
        print(colored("="*30,'dark_grey'))
        
        
        
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.threads
        ) as executor:
            for _ in range(args.threads):
                executor.submit(scan_thread, host, scan_type, port_queue)
        port_queue.join()

if __name__ == "__main__":
    main()
    