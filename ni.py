from queue import PriorityQueue, Queue
import cmd
from langchain_core.runnables.graph_ascii import draw_ascii
from ipaddress import IPv4Address, IPv6Address
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import send, sr1
from ni_header import NIHeader
import ni_header

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
        vertices = {}
        elem_to_vert = {}
        edges = []
        ctr = 1
        for element in self.elements.values():
            vertices[ctr] = str(element)
            elem_to_vert[str(element)] = ctr
            ctr += 1
        for element in self.elements.values():
            for lower_key in element.lower:
                edges.append((elem_to_vert[str(element)], elem_to_vert[lower_key], None, None))
        print(draw_ascii(vertices, edges))

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
        print(f"Using host: {self.host.name} with address {self.host.address}")

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

    def do_init_var(self, arg):
        "Initialize a variable with a security level: init_var <var_name> <conf_level> <integ_level>"
        parts = arg.strip().split()
        if len(parts) != 3:
            print("Usage: init_var <var_name> <conf_level> <integ_level>")
            return
        var_name, conf_level, integ_level = parts
        level_key = f"{conf_level},{integ_level}"
        if level_key not in self.nicxt.lattice.elements:
            print(f"Security level {level_key} not found in lattice.")
            return
        self.nicxt.var_store[var_name] = NIVar(name=var_name, level=self.nicxt.lattice.elements[level_key])
        print(f"Variable '{var_name}' initialized with level {level_key}.")

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
            default_level = self.nicxt.lattice.elements.get("L,L")
            if default_level is None:
                print("Default security level L,L not found in lattice.")
                return
            self.nicxt.var_store[var_name] = NIVar(name=var_name, level=default_level, value=None, vtype=vtype)
        
        if val in self.nicxt.var_store:
            src_level = self.nicxt.var_store[val].level
            dest_level = self.nicxt.var_store[var_name].level
            if not self.nicxt.lattice.less_or_equal(src_level, dest_level):
                print(f"Security violation: cannot flow from {src_level} to {dest_level}.")
                return
            val = self.nicxt.var_store[val].value
        
        self.nicxt.var_store[var_name].value = val
        self.nicxt.var_store[var_name].has_value = True
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
        if not var.has_value:
            print(f"Variable '{var_name}' has no value assigned.")
            return
        print(f"Variable '{var_name}': Value={var.value}, Type={var.vtype}, Level={var.level}")

    def do_dump_vars(self, arg):
        "Dump all variables and their values: dump_vars"
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
        signature = 0  # TODO: signature generation
        
        pkt = IP(dst=str(dest_host.address))/NIHeader(level=self.nicxt.lattice.element_ids[level],
                                                      enc=encrypted, sig=signature)/Raw(load=data.encode())
        send(pkt)
        print(f"Packet sent from {self.host.name} to {dest_host.name}.")


    def do_exit(self, arg):
        "Exit the NI command interface."
        print("Exiting NI command interface.")
        return True
    
    def do_quit(self, arg):
        "Exit the NI command interface."
        return self.do_exit(arg)