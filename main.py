from ni import NICmd
import cmd
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Non-Interference Information Flow Control System")
    parser.add_argument('--config', type=str, help='Path to configuration file to load on startup')
    parser.add_argument('host', type=str, help='The host to simulate')
    args = parser.parse_args()
    maincmd = NICmd(host=args.host, config_file=args.config)
    maincmd.cmdloop()