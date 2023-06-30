import hashlib
import time

import threshold_crypto as tc
from threshold_crypto import CurveParameters
from gmpy2 import mpz, random_state, mpz_random, powmod, mul, f_mod, add, sub


class Curve:
    def __init__(self, label):
        self.cp = CurveParameters(label)
        self.label = label

    def get_pars(self):
        return self.cp

    def raise_p(self, exponent):
        return self.get_pars().P * exponent

    def get_random(self):
        return tc.number.random_in_range(2, self.cp.order)

    def hash_to_mpz(self, input_string):
        hashed_string = hashlib.sha256(
            str(input_string).encode("UTF-8")
        ).hexdigest()
        return mpz("0x" + hashed_string) % self.cp.order

    def get_random_n(self, n):
        rand_list = []
        for i in range(0, n):
            rand_list.append(self.get_random())
        return rand_list

    def mul_mod_q(self, a, b):
        return (a * b) % self.cp.order

    def mul_mod_p(self, a, b):
        return f_mod(mul(a, b), self.p)

    def add_mod_q(self, a, b):
        return (a + b) % self.cp.order

    def add_mod_p(self, a, b):
        return f_mod(add(a, b), self.p)

    def sub_mod_q(self, a, b):
        return f_mod(sub(a, b), self.q)

    def sub_mod_p(self, a, b):
        return f_mod(sub(a, b), self.p)
