from queue import PriorityQueue, Queue


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

    def add_element(self, element: LatticeElement):
        key = f"{element.c},{element.i}"
        self.elements[key] = element
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