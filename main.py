from ni import NICmd
import cmd
import argparse
import logging
import subprocess
from scapy.config import conf

def sync_kernel_arp_to_scapy():
    """
    Sync the kernel's ARP/neighbor table into Scapy's netcache.
    This lets Scapy reuse MAC addresses the kernel already knows.
    """
    try:
        out = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL).decode()
    except Exception as e:
        logging.warning(f"Failed to read kernel ARP table: {e}")
        return
    for line in out.splitlines():
        parts = line.split()
        # Expected format: "IP dev IFACE lladdr MAC STATE"
        if len(parts) >= 5 and parts[3] == "lladdr":
            ip = parts[0]
            mac = parts[4]
            conf.netcache.arp_cache[ip] = mac
    logging.info(f"Synced kernel ARP table to Scapy netcache: {conf.netcache.arp_cache}")

if __name__ == "__main__":
    sync_kernel_arp_to_scapy()
    logging.basicConfig(filename=f"ni.log", level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    parser = argparse.ArgumentParser(description="Non-Interference Information Flow Control System")
    parser.add_argument('--config', type=str, help='Path to configuration file to load on startup')
    parser.add_argument('host', type=str, help='The host to simulate')
    parser.add_argument('iface', type=str, help='The network interface to use')
    args = parser.parse_args()
    maincmd = NICmd(host=args.host, iface=args.iface, config_file=args.config)
    maincmd.cmdloop()