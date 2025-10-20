from ni import NIContext

if __name__ == "__main__":
    nicxt = NIContext('config.txt')
    nicxt.lattice.dump_lattice()