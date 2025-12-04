from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw, Packet
from scapy.sendrecv import send, sniff, sr1
from scapy.config import conf
from ni_header import NIHeader, NIPktType
import subprocess
import argparse
import json

def sync_kernel_arp_to_scapy():
    """
    Sync the kernel's ARP/neighbor table into Scapy's netcache.
    This lets Scapy reuse MAC addresses the kernel already knows.
    """
    try:
        out = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode()
    except Exception as e:
        return
    for line in out.splitlines():
        parts = line.split()
        # Expected format: "IP dev IFACE lladdr MAC STATE"
        if len(parts) >= 5 and parts[3] == "lladdr":
            ip = parts[0]
            mac = parts[4]
            conf.netcache.arp_cache[ip] = mac

if __name__ == "__main__":
    sync_kernel_arp_to_scapy()

    parser = argparse.ArgumentParser(description="Send a phony NI packet")
    parser.add_argument('src_ip', type=str, help='Source IP address')
    parser.add_argument('dest_ip', type=str, help='Destination IP address')
    parser.add_argument('--iface', type=str, help='Network interface to send the packet on')
    parser.add_argument('--level', type=int, help='Security level ID')
    parser.add_argument('--enc', action='store_true', help='Set if the packet is encrypted')
    parser.add_argument('--pkt_type', type=str, choices=['ACK', 'READ', 'WRITE', 'RESPONSE'], default='READ', help='Packet type')
    parser.add_argument('--var_name', type=str, help='Variable name for READ/WRITE packets')
    parser.add_argument('--var_value', type=str, help='Variable value for WRITE packets')
    args = parser.parse_args()

    if args.pkt_type == 'READ' and not args.enc:
        data = {"var_name": args.var_name}
        pkt = IP(src=args.src_ip, dst=args.dest_ip)/NIHeader(level=args.level or 0, enc=0, session=1,
                                                            pkt_type=NIPktType.READ)/Raw(load=json.dumps(data).encode())
        resp = sr1(pkt, iface=args.iface, verbose=False)
        print("Sending READ packet...")
        if resp and Raw in resp:
            print(f"Received response: {resp[Raw].load.decode()}")
        else:
            print("No response received.")
    elif args.pkt_type == 'WRITE' and not args.enc:
        data = {"var_name": args.var_name, "var_value": args.var_value}
        pkt = IP(src=args.src_ip, dst=args.dest_ip)/NIHeader(level=args.level or 0, enc=0, session=1,
                                                            pkt_type=NIPktType.WRITE)/Raw(load=json.dumps(data).encode())
        print("Sending WRITE packet...")
        resp = sr1(pkt, iface=args.iface, verbose=False)
        if resp and Raw in resp:
            print(f"Received response: {resp[Raw].load.decode()}")
        else:
            print("No response received.")

                                                            
