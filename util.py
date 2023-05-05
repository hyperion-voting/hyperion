from gmpy2 import f_mod, mul

def multi_dim_index(list, key):
    """index() for 2D lists.
    """
    for item in list:
        if item[0] == key:
            return item
    return None


def print_bb(bb):
    """Prints the contents of a bulletin board.
    """
    for item in bb:
        print(item)


def find_entry_by_id(id, items):
    """Returns an entry from a given list of entries

    Args:
        id (str): The value of the 'id' field of the entry to return

    Returns:
        The entry if found, None otherwise.
    """
    for item in items:
        if item.id == id:
            return item
    return None


def calculate_voter_term(group, id, teller_registry):
    """Returns an entry from a given list of entries

    Args:
        id (str): The value of the 'id' field of the entry to return

    Returns:
        The entry if found, None otherwise.
    """
    temp = 1

    for item in teller_registry:
        if item["id"] == id:
            temp = f_mod(mul(temp, item["g_r"]), group.p)
    return temp


def find_entry_by_comm(comm, items):
    """Returns an entry from a given list of entries

    Args:
        comm (str): The value of the 'comm' field of the entry to return

    Returns:
        The entry if found, None otherwise.
    """
    for item in items:
        if item["comm"] == comm:
            return item
    return None
