from Crypto.PublicKey import ECC
from typing import Iterable, List, Any, Dict

import threshold_crypto as tc


def deserialize_pd(curve, pd):
    yc_1 = ECC.EccPoint(pd["yc1"]["x"], pd["yc1"]["y"], pd["yc1"]["curve"])
    return tc.data.PartialDecryption(pd["x"], yc_1, curve)


def deserialize_ep(dict_str):
    if (isinstance(dict_str, int)) and (dict_str == 0):
        return ECC.EccPoint(0, 0, "P-256")
    return ECC.EccPoint(dict_str["x"], dict_str["y"], dict_str["curve"])


def _ecc_key_to_serializable(p: ECC.EccKey) -> Dict[str, Any]:
    x, y = p.pointQ.xy
    return {"x": int(x), "y": int(y)}


def serialize_pd(pd):
    return {"x": pd.x, "yc1": tc.data._ecc_point_to_serializable(pd.yC1)}


def multi_dim_index(list, key):
    """index() for 2D lists."""
    for item in list:
        if item[0] == key:
            return item
    return None


def print_bb(bb):
    """Prints the contents of a bulletin board."""
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


def calculate_voter_term(curve, id, teller_registry):
    """Returns an entry from a given list of entries

    Args:
        id (str): The value of the 'id' field of the entry to return

    Returns:
        The entry if found, None otherwise.
    """
    temp = 0

    for item in teller_registry:
        if item["id"] == id:
            if not isinstance(item["g_r"], ECC.EccPoint):
                item["g_r"] = ECC.EccPoint(
                    item["g_r"]["x"], item["g_r"]["y"], item["g_r"]["curve"]
                )
            if temp == 0:
                temp = item["g_r"]
            else:
                temp = temp + item["g_r"]
    return temp


def find_entry_by_comm(comm, items):
    """Returns an entry from a given list of entries

    Args:
        comm (str): The value of the 'comm' field of the entry to return

    Returns:
        The entry if found, None otherwise.
    """
    for item in items:
        point = ECC.EccPoint(
            item["comm"]["x"], item["comm"]["y"], item["comm"]["curve"]
        )
        if point == comm:
            return item
    return None
