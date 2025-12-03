from ni import NICmd
import cmd
import argparse
import logging

if __name__ == "__main__":
    logging.basicConfig(filename=f"ni.log", level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s')
    parser = argparse.ArgumentParser(description="Non-Interference Information Flow Control System")
    parser.add_argument('--config', type=str, help='Path to configuration file to load on startup')
    parser.add_argument('host', type=str, help='The host to simulate')
    parser.add_argument('iface', type=str, help='The network interface to use')
    args = parser.parse_args()
    maincmd = NICmd(host=args.host, iface=args.iface, config_file=args.config)
    maincmd.cmdloop()