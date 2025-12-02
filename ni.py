from queue import PriorityQueue, Queue
from threading import Thread
import cmd
from dagascii.dagascii import draw as draw_ascii
from ipaddress import IPv4Address, IPv6Address
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.packet import Raw, Packet
from scapy.sendrecv import send, sniff
from ni_header import NIHeader
import json
import logging

class LatticeElement():
    """
    An element within a security lattice. Has the following attributes:
    - c: confidentiality level
    - i: integrity level
    - upper: LatticeElements directly greater than this one, as a set
    - lower: LatticeElements directly less than this one, as a set
    """

    def __init__(
            self,
            c: str,
            i: str,
            upper: set[str] | None = None,
            lower: set[str] | None = None):
        self.c = c
        self.i = i
        self.upper = upper if upper is not None else set()
        self.lower = lower if lower is not None else set()

    def __str__(self):
        return f"{self.c},{self.i}"

    def __repr__(self):
        return f"LatticeElement(c={self.c}, i={self.i}, upper={self.upper}, lower={self.lower})"
    
    def add_upper(self, element: str):
        self.upper.add(element)

    def del_upper(self, element: str):
        self.upper.remove(element)
    
    def add_lower(self, element: str):
        self.lower.add(element)

    def del_lower(self, element: str):
        self.lower.remove(element)

class Lattice():
    """
    A confidentiality-integrity security lattice, composed of LatticeElements.
    Starts with 'L' and 'H' levels for both confidentiality and integrity, which
    use the standard definition where L <= H for confidentiality and H <= L for integrity.
    With no additional levels, this is a diamond lattice:
            (H, L)
            /    \\
        (H, H) (L, L)
            \\    /
            (L, H)
    """

    def __init__(self, c_levels: list[list[str]] = [['L'], ['H']], i_levels: list[list[str]] = [['H'], ['L']]):
        self.elements: dict[str, LatticeElement] = {}
        self.element_ids: dict[str, int] = {}
        self.ids_element: dict[int, str] = {}
        self.id_ctr = 1
        q = Queue()

        c_dict = {}
        i_dict = {}
        for c_level_idx in range(len(c_levels)):
            for c_level in c_levels[c_level_idx]:
                c_dict[c_level] = c_level_idx
        for i_level_idx in range(len(i_levels)):
            for i_level in i_levels[i_level_idx]:
                i_dict[i_level] = i_level_idx
        lower = f'{c_levels[0][0]},{i_levels[0][0]}'
        self.add_element(LatticeElement(c_levels[0][0], i_levels[0][0]))
        q.put(lower)
        while not q.empty():
            current = q.get()
            c, i = current.split(',')
            c_idx = c_dict[c]
            i_idx = i_dict[i]
            if c_idx + 1 < len(c_levels):
                for next_c in c_levels[c_idx + 1]:
                    next_elem = f'{next_c},{i}'
                    if next_elem not in self.elements:
                        self.add_element(LatticeElement(next_c, i, lower={current}))
                        q.put(next_elem)
                    else:
                        if current == 'A,L' and next_elem == 'H,L':
                            print("Debug")
                            print(self.elements[current].upper)
                            print(self.elements[next_elem].lower)
                        self.elements[next_elem].add_lower(current)
                        self.elements[current].add_upper(next_elem)
            if i_idx + 1 < len(i_levels):
                for next_i in i_levels[i_idx + 1]:
                    next_elem = f'{c},{next_i}'
                    if next_elem not in self.elements:
                        self.add_element(LatticeElement(c, next_i, lower={current}))
                        q.put(next_elem)
                    else:
                        self.elements[next_elem].add_lower(current)
                        self.elements[current].add_upper(next_elem)

    def __str__(self):
        return '\n'.join([str(elem) for elem in self.elements.values()])
    
    def dump_lattice(self):
        for key, elem in self.elements.items():
            print(f"Element: {key}")
            print(f"  Upper: {elem.upper}")
            print(f"  Lower: {elem.lower}")

    def view_lattice(self):
        vertices = []
        edges = []
        for element in self.elements.values():
            vertices.append(str(element))
            for upper_key in element.upper:
                edges.append((str(element), upper_key))
        print(draw_ascii(vertices, edges))

    def assert_element(self, key: str) -> bool:
        if key in self.elements:
            return True
        raise KeyError(f"Lattice element {key} not found.")

    def get_element(self, key: str) -> LatticeElement:
        self.assert_element(key)
        return self.elements[key]

    def add_element(self, element: LatticeElement):
        key = f"{element.c},{element.i}"
        self.elements[key] = element
        self.element_ids[key] = self.id_ctr
        self.ids_element[self.id_ctr] = key
        self.id_ctr += 1
        found_uppers = []
        for upper_key in element.upper:
            if upper_key in self.elements:
                self.elements[upper_key].add_lower(key)
                found_uppers.append(upper_key)
        for lower_key in element.lower:
            if lower_key in self.elements:
                self.elements[lower_key].add_upper(key)
                for upper_key in found_uppers:
                    if upper_key in self.elements[lower_key].upper:
                        self.elements[upper_key].del_lower(lower_key)
                        self.elements[lower_key].del_upper(upper_key)

    def _bfs_common_bound(self, start1: str, start2: str, direction: str) -> str | None:
        """
        Searches for the closest common bound between two elements using BFS.
        For each element, explores in the specified direction and records distance of each element.
        Chooses the element with the smallest combined distance.
        """
        cbound = None
        visited = set()
        dists: dict[str, int] = {}
        pq = PriorityQueue()
        pq.put((0, start1))
        dists[start1] = 0
        while not pq.empty():
            dist, current_key = pq.get()
            if current_key in visited:
                continue
            visited.add(current_key)
            neighbors = (self.elements[current_key].upper if direction == 'up'
                         else self.elements[current_key].lower)
            for neighbor_key in neighbors:
                pq.put((dist + 1, neighbor_key))
                dists[neighbor_key] = dist + 1
        visited = set()
        pq.put((0, start2))
        min_dist = 0
        while not pq.empty():
            dist, current_key = pq.get()
            if current_key in visited:
                continue
            visited.add(current_key)
            if current_key in dists:
                total_dist = dists[current_key] + dist
                if cbound is None or total_dist < min_dist:
                    min_dist = total_dist
                    cbound = current_key
            neighbors = (self.elements[current_key].upper if direction == 'up'
                         else self.elements[current_key].lower)
            for neighbor_key in neighbors:
                pq.put((dist + 1, neighbor_key))
        return cbound

    def join(self, elem1: LatticeElement, elem2: LatticeElement) -> LatticeElement | None:
        """
        Returns the least upper bound of two lattice elements.
        """
        lub_key = self._bfs_common_bound(str(elem1), str(elem2), 'up')
        return self.elements[lub_key] if lub_key else None
    
    def meet(self, elem1: LatticeElement, elem2: LatticeElement) -> LatticeElement | None:
        """
        Returns the greatest lower bound of two lattice elements.
        """
        glb_key = self._bfs_common_bound(str(elem1), str(elem2), 'down')
        return self.elements[glb_key] if glb_key else None
    
    def less_or_equal(self, elem1: LatticeElement, elem2: LatticeElement) -> bool:
        """
        Returns True if elem1 <= elem2 in the lattice, False otherwise.
        """
        visited = set()
        q = Queue()
        q.put(str(elem1))
        while not q.empty():
            current_key = q.get()
            if current_key == str(elem2):
                return True
            visited.add(current_key)
            for upper_key in self.elements[current_key].upper:
                if upper_key not in visited:
                    q.put(upper_key)
        return False
    
    def minimum_element(self) -> LatticeElement | None:
        """
        Returns the minimum element in the lattice, if it exists.
        """
        for element in self.elements.values():
            if not element.lower:
                return element
        return None
    
    def maximum_element(self) -> LatticeElement | None:
        """
        Returns the maximum element in the lattice, if it exists.
        """
        for element in self.elements.values():
            if not element.upper:
                return element
        return None
    
class NIHost():
    """
    A node in a non-interference information flow graph. Has the following attributes:
    - name: the name of the node
    - level: the security level of the node (a LatticeElement)
    - edges: a set of names of nodes this node has edges to
    """

    def __init__(self, name: str, level: LatticeElement, address: IPv4Address | IPv6Address | None = None):
        self.name = name
        self.level = level
        self.edges: set[str] = set()
        self.address: IPv4Address | IPv6Address | None = address
        if address is not None:
            self.address_type = type(address).__name__
        else:
            self.address_type = None

    def add_edge(self, to_node: str):
        self.edges.add(to_node)

    def del_edge(self, to_node: str):
        self.edges.remove(to_node)

    def set_address(self, address: IPv4Address | IPv6Address):
        self.address = address
        self.address_type = type(address).__name__

    def __repr__(self):
        return f"NIHost(name={self.name}, level={self.level}, edges={self.edges}, address={self.address})"
    
class NIVar():
    """
    A variable in the non-interference information flow system. Has the following attributes:
    - name: the name of the variable
    - level: the security level of the variable (a LatticeElement)
    - value: the current value of the variable
    - vtype: the type of the variable ('int' or 'str')
    - has_value: whether the variable has been assigned a value
    """

    def __init__(self, name: str, level: LatticeElement, value: int | str | None = None, vtype: str = 'int'):
        self.name = name
        self.level = level
        self.value = value
        self.vtype = vtype
        self.has_value = value is not None

    def __repr__(self):
        return f"NIVar(name={self.name}, level={self.level}, value={self.value})"
    
class NIException(Exception):
    """
    Custom exception class for NI-related errors.
    """
    def __init__(self, message: str):
        super().__init__(f"Security Exception: {message}")
    
class NIContext():
    """
    A context built from a given configuration file. Holds the following:
    - c_levels: confidentiality levels used in this context
    - i_levels: integrity levels used in this context
    - lattice: the security lattice used in this context
    """

    def __init__(self, config_file: str = ''):
        self.c_levels: list[list[str]] = []
        self.i_levels: list[list[str]] = []
        self.lattice: Lattice = Lattice()
        self.var_store: dict[str, NIVar] = {}
        self.hosts: dict[str, NIHost] = {}
        if config_file:
            self.build_from_config(config_file)
        self.var_store_max_lvl = self.lattice.minimum_element()
        self.pc_level = self.lattice.minimum_element()
        self.auth_level = self.lattice.minimum_element()

    def build_from_config(self, config_file: str):
        self.c_levels: list[list[str]] = []
        self.i_levels: list[list[str]] = []
        self.lattice: Lattice

        with open(config_file, 'r') as f:
            lines = f.readlines()
        
        mode = None
        for line in lines:
            line = line.strip()
            if line == '':
                continue
            if line.startswith('#'):
                continue
            if line == '[Confidentiality Levels]':
                mode = 'c'
                continue
            elif line == '[Integrity Levels]':
                mode = 'i'
                continue
            elif line == '[Resources]':
                mode = 'r'
                continue
            if mode == 'c':
                levels = [lvl.strip() for lvl in line.split(',')]
                self.c_levels.append(levels)
            elif mode == 'i':
                levels = [lvl.strip() for lvl in line.split(',')]
                self.i_levels.append(levels)
            elif mode == 'r':
                parts = [part.strip() for part in line.split(',')]
                name = parts[0]
                rtype = parts[1]
                if rtype == 'h':
                    c_level = parts[2]
                    i_level = parts[3]
                    address_str = parts[4]
                    level_key = f"{c_level},{i_level}"
                    if level_key not in self.lattice.elements:
                        raise ValueError(f"Security level {level_key} not found in lattice.")
                    level = self.lattice.elements[level_key]
                    try:
                        if ':' in address_str:
                            address = IPv6Address(address_str)
                        else:
                            address = IPv4Address(address_str)
                    except ValueError:
                        raise ValueError(f"Invalid IP address: {address_str}")
                    host = NIHost(name=name, level=level, address=address)
                    self.hosts[name] = host
        self.lattice = Lattice(self.c_levels, self.i_levels)

    def increase_pc_level(self, level: LatticeElement):
        """
        Increase the current PC level to the join of the current PC level and the given level.
        """
        new_pc_level = self.lattice.join(self.pc_level, level)
        if new_pc_level is not None:
            if new_pc_level != self.pc_level:
                self.set_pc_level(new_pc_level)
        else:
            raise NIException("Failed to increase PC level; no common upper bound found.")

    def set_pc_level(self, level: LatticeElement):
        """
        Set the current PC level.
        """
        self.pc_level = level
        print(f"PC level set to {level}.")

    def set_auth_level(self, level: LatticeElement):
        """
        Set the current authentication level.
        """
        self.auth_level = level
        print(f"Auth level set to {level}.")

    def pcdecl(self, level_from: LatticeElement, level_to: LatticeElement, verbose: bool = False):
        """
        Change the PC level, from "Reconciling Progress-Insensitive Noninterference and Declassification"
        by Johan Bay and Aslan Askarov, 2020.
        """
        if verbose:
            print(f"Join: {self.lattice.join(self.auth_level, level_to)}")
            print(f"Less or equal: {self.lattice.less_or_equal(level_from, self.lattice.join(self.auth_level, level_to))}")
        if not self.lattice.less_or_equal(level_from, self.lattice.join(self.auth_level, level_to)):
            raise NIException("Invalid PC downgrade, cannot downgrade to a lower level " \
                              "without proper authority.") 
        self.set_pc_level(level_to)

    def assert_level_pc(self, level: LatticeElement):
        """
        Assert that the PC level is less than or equal to the given level.
        """
        if not self.lattice.less_or_equal(self.pc_level, level):
            raise NIException("PC level not less or equal to the given level.")

class NICmd(cmd.Cmd):
    """
    Command-line interface for interacting with the NIContext.
    """

    intro = "Non-Interference Information Flow Control System. Type 'help' for commands."
    prompt = "ni> "

    def __init__(self, host: str, config_file: str = ''):
        super().__init__()
        self.nicxt = NIContext(config_file=config_file)
        if host not in self.nicxt.hosts:
            raise ValueError(f"Host '{host}' not found in context.")
        self.host = self.nicxt.hosts[host]
        self.prompt = f"{self.host.name}> "
        self.nicxt.set_auth_level(self.host.level)
        print(f"Using host: {self.host.name} with address {self.host.address}")
        self.shared_queue = Queue()
        self.packet_listener = Thread(target=sniff, kwargs={
            'filter': f"ip dst {self.host.address} and ip proto 254",
            'prn': lambda pkt: self.process_packet(pkt, self.shared_queue)
        })
        self.packet_listener.daemon = True
        self.packet_listener.start()
        logging.info(f"NICmd initialized for host {self.host.name} with address {self.host.address}.")

    def process_packet(self, packet: Packet, queue: Queue):
        """
        Listens for incoming NI packets and processes them.
        """
        if not NIHeader in packet:
            return
        ni_header = packet[NIHeader]
        src = None
        if IP in packet:
            src = IPv4Address(packet[IP].src)
        elif IPv6 in packet:
            src = IPv6Address(packet[IPv6].src)
        logging.info(f"Received packet from {packet[IP].src} to {packet[IP].dst} with level {level_key}")
        level_id = ni_header.level
        pkt_type = ni_header.pkt_type
        session = ni_header.session
        if pkt_type == "ACK" or pkt_type == "RESPONSE":
            queue.put(packet)
            return
        elif pkt_type not in ["READ", "WRITE"]:
            return
        level_key = self.nicxt.lattice.ids_element.get(level_id, None)
        if level_key is None:
            print(f"Received packet with unknown level ID: {level_id}")
            return
        level = self.nicxt.lattice.get_element(level_key)
        data = json.loads(packet[Raw].load.decode())

        if pkt_type == "READ":
            # For reading, the sender is requesting with their auth as level
            var_name = data.get("var_name", "")
            if var_name not in self.nicxt.var_store:
                logging.warning(f"Variable '{var_name}' not found for READ request from {src}.")
                self.send_packet(src, level=level, encrypted=ni_header.enc,
                                 pkt_type="RESPONSE", session=session,
                                 data={"error": "Variable not found"})
                return
            var = self.nicxt.var_store[var_name]
            if not self.nicxt.lattice.less_or_equal(var.level, level):
                logging.warning(f"Unauthorized READ request for variable '{var_name}' from {src}.")
                self.send_packet(src, level=level, encrypted=ni_header.enc,
                                 pkt_type="RESPONSE", session=session,
                                 data={"error": "Unauthorized access"})
                return
            logging.info(f"Processing READ request for variable '{var_name}' from {src}.")
            self.send_packet(src, level=level, encrypted=ni_header.enc,
                             pkt_type="RESPONSE", session=session,
                             data={"var_name": var_name, "value": var.value, "vtype": var.vtype})
            return
        elif pkt_type == "WRITE":
            # For writing, the sender is providing data with the val level as level
            var_name = data.get("var_name", "")
            value = data.get("value", None)
            vtype = data.get("vtype", "int")
            if var_name not in self.nicxt.var_store:
                logging.warning(f"Variable '{var_name}' not found for WRITE request from {src}.")
                if not self.init_var(var_name, level.c, level.i):
                    self.send_packet(src, level=level, encrypted=ni_header.enc,
                                     pkt_type="RESPONSE", session=session,
                                     data={"error": "Variable not found and initialization failed"})
                    return
            var = self.nicxt.var_store[var_name]
            if not self.nicxt.lattice.less_or_equal(level, var.level):
                logging.warning(f"Unauthorized WRITE request for variable '{var_name}' from {src}.")
                self.send_packet(src, level=level, encrypted=ni_header.enc,
                                 pkt_type="RESPONSE", session=session,
                                 data={"error": "Unauthorized access"})
                return
            var.value = value
            var.vtype = vtype
            var.has_value = True
            logging.info(f"Processed WRITE request for variable '{var_name}' from {src}.")
            self.send_packet(src, level=level, encrypted=ni_header.enc,
                             pkt_type="RESPONSE", session=session,
                             data={"status": "Success"})
            return

    def send_packet(self, dest: IPv4Address | IPv6Address, level: LatticeElement,
                    encrypted: int, pkt_type: str, session: int, data) -> None:
        """
        Send a packet from the current host to the destination host with the given security level.
        """
        signature = 0  # TODO: signature generation
        pkt = None
        #TODO: Ensure that type works with string args for the enum
        rawdata = json.dumps(data)
        if type(dest) == IPv4Address:
            pkt = IP(dst=str(dest))/NIHeader(level=self.nicxt.lattice.element_ids[str(level)],
                                             enc=encrypted, pkt_type=pkt_type, session=session,
                                             sig=signature)/Raw(load=rawdata.encode())
        elif type(dest) == IPv6Address:
            pkt = IPv6(dst=str(dest))/NIHeader(level=self.nicxt.lattice.element_ids[str(level)],
                                             enc=encrypted, pkt_type=pkt_type, session=session,
                                             sig=signature)/Raw(load=rawdata.encode())
        send(pkt)
        print(f"Packet sent from {self.host.name} to {dest}.")
    
    def do_load_config(self, arg):
        "Load a configuration file: load_config <filename>"
        filename = arg.strip()
        if not filename:
            print("Please provide a configuration file name.")
            return
        try:
            self.nicxt.build_from_config(filename)
            print(f"Configuration loaded from {filename}.")
        except Exception as e:
            print(f"Error loading configuration: {e}")

    def do_show_lattice(self, arg):
        "Show the security lattice: show_lattice <'view'|'dump'>"
        mode = arg.strip().lower()
        if mode == 'dump':
            self.nicxt.lattice.dump_lattice()
        elif mode == 'view':
            self.nicxt.lattice.view_lattice()
        else:
            print("Invalid argument. Use 'view' or 'dump'.")

    def do_status(self, arg):
        "Show the current host status: status"
        print(f"Host: {self.host.name}")
        print(f"Address: {self.host.address}")
        print(f"Level: {self.host.level}")
        print(f"PC Level: {self.nicxt.pc_level}")
        print(f"Auth Level: {self.nicxt.auth_level}")

    def init_var(self, var_name: str, conf_level: str, integ_level: str):
        """
        Initialize a variable with the given security level.
        """
        level_key = f"{conf_level},{integ_level}"
        try:
            level = self.nicxt.lattice.get_element(level_key)
            self.nicxt.assert_level_pc(level)
            self.nicxt.var_store[var_name] = NIVar(name=var_name, level=level)
            self.nicxt.var_store_max_lvl = self.nicxt.lattice.join(self.nicxt.var_store_max_lvl, level)
        except KeyError as ke:
            print(ke)
            return False
        except NIException as nie:
            print(nie)
            return False
        except Exception as e:
            print(f"Error initializing variable: {e}")
            return False

    def do_init_var(self, arg):
        "Initialize a variable with a security level: init_var <var_name> <conf_level> <integ_level>"
        parts = arg.strip().split()
        if len(parts) != 3:
            print("Usage: init_var <var_name> <conf_level> <integ_level>")
            return
        var_name, conf_level, integ_level = parts
        if not self.init_var(var_name, conf_level, integ_level):
            return
        print(f"Variable '{var_name}' initialized with level {conf_level},{integ_level}.")

    def do_set_var(self, arg):
        "Set a variable's value (default int): set_var <var_name> <value|var_name> <type=str|int>"
        parts = arg.strip().split()
        val = None
        vtype = 'int'
        if len(parts) > 3 or len(parts) < 2:
            print("Usage: set_var <var_name> <value|var_name> <type=str|int>")
            return
        elif len(parts) == 2:
            var_name, val = parts
        else:
            var_name, val, vtype = parts
        
        if var_name not in self.nicxt.var_store:
            print(f"Variable '{var_name}' not initialized. Initializing with default level L,L.")
            self.do_init_var(f"{var_name} L L")
            if var_name not in self.nicxt.var_store:
                return
        
        src_level = self.nicxt.lattice.minimum_element()
        dest_level = self.nicxt.var_store[var_name].level
        if val in self.nicxt.var_store:
            if not self.nicxt.var_store[val].has_value:
                print(f"Variable '{val}' has no value assigned.")
                return
            src_level = self.nicxt.var_store[val].level
            val = self.nicxt.var_store[val].value

        try:
            sec_level = self.nicxt.lattice.join(self.nicxt.pc_level, src_level)
            # Dynamic assignment check from Bay and Askarov 2020
            if not self.nicxt.lattice.less_or_equal(sec_level, dest_level):
                raise NIException(f"Level of value ({src_level}) join pc ({self.nicxt.pc_level}) ({sec_level}) "
                                  f"must be <= destination ({dest_level}).")
            self.nicxt.var_store[var_name].value = val
            self.nicxt.var_store[var_name].has_value = True
        except KeyError as ke:
            print(ke)
            return
        except NIException as nie:
            print(nie)
            return
        except Exception as e:
            print(f"Error setting variable: {e}")
            return
        
        if vtype == 'int' and val is not None:
            try:
                val = int(val)
            except ValueError:
                print("Non-integer value, assuming string type.")
                vtype = 'str'
        
        if vtype != self.nicxt.var_store[var_name].vtype:
            print(f"Changing variable '{var_name}' type from {self.nicxt.var_store[var_name].vtype} to {vtype}.")
            self.nicxt.var_store[var_name].vtype = vtype
        print(f"Variable '{var_name}' set to {val} ({vtype}).")

    def do_print_var(self, arg):
        "Print a variable's value: print_var <var_name>"
        var_name = arg.strip()
        if var_name not in self.nicxt.var_store:
            print(f"Variable '{var_name}' not initialized.")
            return
        var = self.nicxt.var_store[var_name]
        self.nicxt.increase_pc_level(var.level)
        if not var.has_value:
            print(f"Variable '{var_name}' has no value assigned.")
            return
        print(f"Variable '{var_name}': Value={var.value}, Type={var.vtype}, Level={var.level}")

    def do_dump_vars(self, arg):
        "Dump all variables and their values: dump_vars"
        self.nicxt.increase_pc_level(self.nicxt.var_store_max_lvl)
        for var_name, var in self.nicxt.var_store.items():
            if var.has_value:
                print(f"{var_name}: Value={var.value}, Type={var.vtype}, Level={var.level}")
            else:
                print(f"{var_name}: Value=None, Type={var.vtype}, Level={var.level}")

    def do_del_var(self, arg):
        "Delete a variable: del_var <var_name>"
        var_name = arg.strip()
        if var_name not in self.nicxt.var_store:
            print(f"Variable '{var_name}' not initialized.")
            return
        del self.nicxt.var_store[var_name]
        print(f"Variable '{var_name}' deleted.")

    def do_del_all_vars(self, arg):
        "Delete all variables: del_all_vars"
        self.nicxt.var_store.clear()
        print("All variables deleted.")

    def do_clear_vars(self, arg):
        "Clear all variable values without deleting variables: clear_vars"
        for var in self.nicxt.var_store.values():
            var.value = None
            var.has_value = False
        print("All variable values cleared.")

    def do_reset_env(self, arg):
        "Reset the environment, clearing variables and minimizing PC: reset_env"
        self.nicxt.var_store.clear()
        self.nicxt.var_store_max_lvl = self.nicxt.lattice.minimum_element()
        self.nicxt.set_pc_level(self.nicxt.lattice.minimum_element())
        print("Environment reset.")

    def do_send_packet(self, arg):
        "Send a packet from the current host: send_packet <dest_host> <confidentiality> <integrity> <encrypted> <data>"
        args = arg.split()
        if len(args) < 5:
            print("Usage: send_packet <dest_host> <confidentiality> <integrity> <encrypted> <data>")
            return
        dest_host_name = args[0]
        if dest_host_name not in self.nicxt.hosts:
            print(f"Destination host '{dest_host_name}' not found.")
            return
        dest_host = self.nicxt.hosts[dest_host_name]
        level = f"{args[1]},{args[2]}"
        encrypted = int(args[3])
        data = ''.join(args[4:])
        if level not in self.nicxt.lattice.elements:
            print(f"Security level {level} not found in lattice.")
            return
        self.send_packet(dest_host.address, self.nicxt.lattice.elements[level], encrypted, data)

    def do_exit(self, arg):
        "Exit the NI command interface."
        print("Exiting NI command interface.")
        return True
    
    def do_quit(self, arg):
        "Exit the NI command interface."
        return self.do_exit(arg)
    
    #TODO: Remove test command
    def do_test(self, arg):
        args = arg.split()
        self.nicxt.pcdecl(level_from=self.nicxt.lattice.elements[args[0]],
                          level_to=self.nicxt.lattice.elements[args[1]], verbose=True)