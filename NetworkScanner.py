import argparse
import socket
import re
import concurrent.futures
import logging
from queue import Queue
import queue
import scapy.all as scapy

logging.basicConfig(level=logging.INFO, format="%(message)s")


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
        logging.error(
            "[-] Please provide a valid IP address range for ARP ping!")
        exit(1)

    try:
        arp_request_frame = scapy.ARP(pdst=ip)
        ether_broadcast_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        broadcast_arp_packet = ether_broadcast_frame / arp_request_frame
        active_clients = scapy.srp(
            broadcast_arp_packet, timeout=3, verbose=False)[0]
        logging.info("IP address\tMac address")
        for _, reply in active_clients:
            logging.info(f"{reply.psrc}\t{reply.hwsrc}")
    except Exception as err:
        logging.error(f"[-] Error occurred! Reason: {err}")


def port_scan(port, host, scan_type):
    try:
        if scan_type == "T":
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.settimeout(1)
            client.connect((host, port))
            client.close()
            logging.info(f"{port}\tOpen")
        elif scan_type == "U":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            client.connect((host, port))
            logging.info(f"{port}\tOpen")
            sock.close()
    except KeyboardInterrupt:
        logging.error("You pressed Ctrl+C")
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

    if args.arp:
        logging.info(
            "\n----------------------------------------\n\tARP Ping Scan Results \n-----------------------------------------"
        )
        arp_ping(host)

    if args.tcpPortScan:
        logging.info(
            "\n----------------------------------------\n\tTCP Port Scan Results \n-----------------------------------------"
        )
        logging.info(
            "---------------------------\nPort\tState\n---------------------------"
        )
        scan_type = "T"
        for port in range(start_port, end_port + 1):
            port_queue.put(port)
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=args.threads
        ) as executor:
            for _ in range(args.threads):
                executor.submit(scan_thread, host, scan_type, port_queue)
        port_queue.join()

    if args.udpPortScan:
        logging.info(
            "\n----------------------------------------\n\tUDP Port Scan Results \n-----------------------------------------"
        )
        logging.info(
            "---------------------------\nPort\tState\n---------------------------"
        )
        scan_type = "U"
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
