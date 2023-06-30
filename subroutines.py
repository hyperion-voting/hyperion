import random
import time
import hashlib
import multiprocessing

from Crypto.PublicKey import ECC
import gmpy2

from util import deserialize_ep

import threshold_crypto as tc

from primitives import ElGamalEncryption, PermutationCommitment

q1 = multiprocessing.Queue()


def gen_permutation(length):
    i = []
    for j in range(length):
        i.append(j)
    random.shuffle(i)
    return i


class Mixnet:
    """A Terelius-Wikström Mixnet

    | From: "Terelius B. & Wikström D. (2010) Proofs of Restricted Shuffles."
    | And:  "Haenni et al. Pseudo-Code Algorithms for Verifiable Re-encryption Mix-Nets."

    Attributes:
        curve (curve): The curve setup of the protocol
    """

    def __init__(self, curve):
        self.curve = curve

    def mp_re_encrypt(self, list, public_key, q1):
        """Parallelized list re-encryption.

        Arguments:
                 list   : A list of tuples containing two ciphertexts
        public_key (mpz): An El Gamal public key

        Returns:
               A list of re-encrypted ciphertexts.
        """
        ege = ElGamalEncryption(self.curve)
        out = []
        for i in range(len(list)):
            index = list[i][0]
            if not isinstance(list[i][1][0], ECC.EccPoint):
                list[i][1][0] = deserialize_ep(list[i][1][0])
                list[i][1][1] = deserialize_ep(list[i][1][1])
            if not isinstance(list[i][2][0], ECC.EccPoint):
                list[i][2][0] = deserialize_ep(list[i][2][0])
                list[i][2][1] = deserialize_ep(list[i][2][1])
            re_encryption = ege.re_encrypt(public_key, list[i][1])
            re_encryption2 = ege.re_encrypt(public_key, list[i][2])
            temp = []
            temp.append(index)
            re_encryption[0] = tc.data._ecc_point_to_serializable(
                re_encryption[0]
            )
            re_encryption[1] = tc.data._ecc_point_to_serializable(
                re_encryption[1]
            )
            re_encryption2[0] = tc.data._ecc_point_to_serializable(
                re_encryption2[0]
            )
            re_encryption2[1] = tc.data._ecc_point_to_serializable(
                re_encryption2[1]
            )
            temp.append(re_encryption)
            temp.append(re_encryption[3])
            temp.append(re_encryption2)
            temp.append(re_encryption2[3])
            out.append(temp)
        q1.put(out)

    def re_encryption_mix(self, list_votes, public_key):
        """A parallel rencryption mixnet function.

        Arguments:
           list_votes   : A list of tuples containing two ciphertexts
        public_key (mpz): An El Gamal public key

        Returns:
               A list of re-encrypted ciphertexts and a shuffle proof.
        """
        count = len(list_votes)
        list_1 = [[0] * 2] * count
        list_r = [[0] * 2] * count
        permutation = gen_permutation(count)
        list_tagged = []
        index = 0
        for item in list_votes:
            temp = []
            temp.append(index)
            temp.append(item[0])
            temp.append(item[1])
            list_tagged.append(temp)
            index = index + 1

        n = multiprocessing.cpu_count()
        k, m = divmod(len(list_tagged), n)
        split_lists = [
            list_tagged[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)]
            for i in range(n)
        ]
        processes = [
            multiprocessing.Process(
                target=self.mp_re_encrypt, args=(ciph, public_key, q1)
            )
            for ciph in split_lists
        ]
        for p in processes:
            p.daemon = True
            p.start()
        data = []
        for p in processes:
            data = data + q1.get()
        for p in processes:
            p.join()
            # p.close()
        data.sort()
        for i in range(len(data)):
            temp = []
            data[i][1][0] = deserialize_ep(data[i][1][0])
            data[i][1][1] = deserialize_ep(data[i][1][1])
            data[i][3][0] = deserialize_ep(data[i][3][0])
            data[i][3][1] = deserialize_ep(data[i][3][1])
            temp.append(data[i][1])
            temp.append(data[i][3])
            list_1[permutation[i]] = temp
            temp = []
            temp.append(data[i][2])
            temp.append(data[i][4])
            list_r[permutation[i]] = temp
        pc = PermutationCommitment(self.curve)
        pc.setup(count)
        permutation_commitment = pc.commit(permutation)
        u = [0] * count
        u_prime = [0] * count
        list_vh = list_votes
        for i in range(len(list_vh)):
            if isinstance(list_vh[i][1][0], ECC.EccPoint):
                lvi_1 = tc.data._ecc_point_to_serializable(list_vh[i][1][0])
                lvi_2 = tc.data._ecc_point_to_serializable(list_vh[i][1][1])
            else:
                lvi_1 = list_vh[i][1][0]
                lvi_2 = list_vh[i][1][1]
            lvi_3 = list_vh[i][1][2]
            list_vh[i][1] = [lvi_1, lvi_2, lvi_3]
        list_1h = list_1

        for i in range(len(list_1h)):
            if isinstance(list_1h[i][0][0], ECC.EccPoint):
                list_1h[i][0][0] = tc.data._ecc_point_to_serializable(
                    list_1h[i][0][0]
                )
                list_1h[i][0][1] = tc.data._ecc_point_to_serializable(
                    list_1h[i][0][1]
                )
                list_1h[i][1][0] = tc.data._ecc_point_to_serializable(
                    list_1h[i][1][0]
                )
                list_1h[i][1][1] = tc.data._ecc_point_to_serializable(
                    list_1h[i][1][1]
                )

        pc_expl = str("")
        for item in permutation_commitment["c"]:
            pc_expl = pc_expl + str(tc.data._ecc_point_to_serializable(item))

        for i in range(count):
            u[i] = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_vh) + str(list_1h) + str(pc_expl) + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                )
                % self.curve.get_pars().order
            )

        for i in range(count):
            u_prime[permutation[i]] = u[i]
        h = self.curve.get_random() * self.curve.get_pars().P
        c = [0] * count
        r = [0] * count
        r_vect = 0
        w_hat = []
        w_prime = []
        for i in range(count):
            r[i] = self.curve.get_random()
            if i == 0:
                c_previous = h
            else:
                c_previous = c[i - 1]
            c[i] = self.curve.raise_p(r[i]) + (c_previous * u_prime[i])
            r_vect = r_vect + permutation_commitment["r"][i]
            w_hat.append(self.curve.get_random())
            w_prime.append(self.curve.get_random())
        v = [0] * count
        v[count - 1] = 1
        for i in range(count - 2, -1, -1):
            v[i] = (u_prime[i + 1] * v[i + 1]) % self.curve.get_pars().order
        r_hat = 0
        r_tilde = 0
        r_prime = 0
        r_prime_2 = 0
        for i in range(count):
            temp = (r[i] * v[i]) % self.curve.get_pars().order
            r_hat = (r_hat + temp) % self.curve.get_pars().order
            temp_tilde = (
                permutation_commitment["r"][i] * u[i]
            ) % self.curve.get_pars().order
            r_tilde = (r_tilde + temp_tilde) % self.curve.get_pars().order
            temp_prime = (
                list_r[i][0] * u_prime[i]
            ) % self.curve.get_pars().order
            r_prime = (r_prime + temp_prime) % self.curve.get_pars().order
            temp_prime = (
                list_r[i][1] * u_prime[i]
            ) % self.curve.get_pars().order
            r_prime_2 = (r_prime_2 + temp_prime) % self.curve.get_pars().order
        w = []
        for i in range(4):
            w.append(self.curve.get_random())
        t1 = self.curve.raise_p(w[0])
        t2 = self.curve.raise_p(w[1])
        t3 = self.curve.raise_p(w[2])
        w_4_inv = (
            self.curve.get_pars().order - w[3]
        ) * self.curve.get_pars().P
        t_4_2 = (self.curve.get_pars().order - w[3]) * self.curve.get_pars().P
        t_4_1 = w_4_inv
        t_4_3 = w_4_inv
        t_4_4 = t_4_2
        t_hat = [0] * count
        for i in range(count):
            t3 = t3 + (pc.get_generators()[i] * w_prime[i])
            t_4_1 = t_4_1 + (deserialize_ep(list_1[i][0][0]) * w_prime[i])
            t_4_3 = t_4_3 + (deserialize_ep(list_1[i][1][0]) * w_prime[i])
            t_4_2 = t_4_2 + (deserialize_ep(list_1[i][0][1]) * w_prime[i])
            t_4_4 = t_4_4 + (deserialize_ep(list_1[i][1][1]) * w_prime[i])
            if i == 0:
                temp = h * w_prime[i]
            else:
                temp = c[i - 1] * w_prime[i]
            t_hat[i] = self.curve.raise_p(w_hat[i]) + temp
        t_hat_expl = str("")
        for item in t_hat:
            t_hat_expl = t_hat_expl + str(
                tc.data._ecc_point_to_serializable(item)
            )

        c_expl = str("")
        for item in c:
            c_expl = c_expl + str(tc.data._ecc_point_to_serializable(item))

        pc_expl = str("")
        for item in permutation_commitment["c"]:
            pc_expl = pc_expl + str(tc.data._ecc_point_to_serializable(item))

        c_hash = hashlib.sha256(
            (
                str(list_vh)
                + str(list_1h)
                + str(pc_expl)
                + str(tc.data._ecc_point_to_serializable(h))
                + str(c_expl)
                + str(tc.data._ecc_point_to_serializable(public_key))
                + str(tc.data._ecc_point_to_serializable(t1))
                + str(tc.data._ecc_point_to_serializable(t2))
                + str(tc.data._ecc_point_to_serializable(t3))
                + str(tc.data._ecc_point_to_serializable(t_4_1))
                + str(tc.data._ecc_point_to_serializable(t_4_2))
                + str(t_hat_expl)
                + str(tc.data._ecc_point_to_serializable(t_4_3))
                + str(tc.data._ecc_point_to_serializable(t_4_4))
            ).encode("UTF-8")
        ).hexdigest()
        c_hash = gmpy2.mpz("0x" + c_hash) % self.curve.get_pars().order
        s_1 = self.curve.add_mod_q(w[0], self.curve.mul_mod_q(c_hash, r_vect))
        s_2 = self.curve.add_mod_q(w[1], self.curve.mul_mod_q(c_hash, r_hat))
        s_3 = self.curve.add_mod_q(w[2], self.curve.mul_mod_q(c_hash, r_tilde))
        s_4 = self.curve.add_mod_q(w[3], self.curve.mul_mod_q(c_hash, r_prime))
        s_5 = self.curve.add_mod_q(
            w[3], self.curve.mul_mod_q(c_hash, r_prime_2)
        )
        s_hat = [0] * count
        s_prime = [0] * count
        for i in range(count):
            s_hat[i] = self.curve.add_mod_q(
                w_hat[i], self.curve.mul_mod_q(c_hash, r[i])
            )
            s_prime[i] = self.curve.add_mod_q(
                w_prime[i], self.curve.mul_mod_q(c_hash, u_prime[i])
            )
        return (
            list_1,
            permutation_commitment,
            c,
            r,
            t1,
            t2,
            t3,
            t_4_1,
            t_4_2,
            t_4_3,
            t_4_4,
            t_hat,
            h,
            s_1,
            s_2,
            s_3,
            s_4,
            s_5,
            s_hat,
            s_prime,
        )

    def verify_mix(
        self,
        public_key,
        list_0,
        list_1,
        permutation_commitment,
        c,
        r,
        t1,
        t2,
        t3,
        t_4_1,
        t_4_2,
        t_4_3,
        t_4_4,
        t_hat,
        h,
        s_1,
        s_2,
        s_3,
        s_4,
        s_5,
        s_hat,
        s_prime,
    ):
        count = len(list_0)
        if count != len(list_1):
            exit()
        u_ver = [0] * count
        c_prod = 0
        h_prod = 0
        u_prod = 1
        c_ver_tilde = 0
        pc_expl = str("")
        for item in permutation_commitment["c"]:
            pc_expl = pc_expl + str(tc.data._ecc_point_to_serializable(item))
        list_vh = list_0
        for i in range(len(list_vh)):
            if isinstance(list_vh[i][1][0], ECC.EccPoint):
                lvi_1 = tc.data._ecc_point_to_serializable(list_vh[i][1][0])
                lvi_2 = tc.data._ecc_point_to_serializable(list_vh[i][1][1])
                lvi_3 = list_vh[i][1][2]
            else:
                lvi_1 = list_vh[i][1][0]
                lvi_2 = list_vh[i][1][1]
                lvi_3 = list_vh[i][1][2]
            list_vh[i][1] = [lvi_1, lvi_2, lvi_3]
        list_1h = list_1

        for i in range(len(list_1h)):
            if isinstance(list_1h[i][1][0], ECC.EccPoint):
                list_1h[i][0][0] = tc.data._ecc_point_to_serializable(
                    list_1h[i][0][0]
                )
                list_1h[i][0][1] = tc.data._ecc_point_to_serializable(
                    list_1h[i][0][1]
                )
                list_1h[i][1][0] = tc.data._ecc_point_to_serializable(
                    list_1h[i][1][0]
                )
                list_1h[i][1][1] = tc.data._ecc_point_to_serializable(
                    list_1h[i][1][1]
                )

        u_ver[0] = (
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    (
                        str(list_vh) + str(list_1h) + str(pc_expl) + str(0)
                    ).encode("UTF8")
                ).hexdigest()
            )
            % self.curve.get_pars().order
        )

        c_prod = permutation_commitment["c"][0]
        h_prod = permutation_commitment["h"][0]

        u_prod = u_ver[0]
        c_ver_tilde = permutation_commitment["c"][0] * u_ver[0]

        for i in range(1, count):
            u_ver[i] = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_vh) + str(list_1h) + str(pc_expl) + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                )
                % self.curve.get_pars().order
            )

            c_prod = c_prod + permutation_commitment["c"][i]

            h_prod = h_prod + permutation_commitment["h"][i]

            u_prod = self.curve.mul_mod_q(u_prod, u_ver[i])
            c_ver_tilde = (
                c_ver_tilde + permutation_commitment["c"][i] * u_ver[i]
            )

        t_hat_expl = str("")
        for item in t_hat:
            t_hat_expl = t_hat_expl + str(
                tc.data._ecc_point_to_serializable(item)
            )

        c_expl = str("")
        for item in c:
            c_expl = c_expl + str(tc.data._ecc_point_to_serializable(item))

        pc_expl = str("")
        for item in permutation_commitment["c"]:
            pc_expl = pc_expl + str(tc.data._ecc_point_to_serializable(item))

        c_ver_vect = c_prod + (-h_prod)
        c_ver_hash = (
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    (
                        str(list_vh)
                        + str(list_1h)
                        + str(pc_expl)
                        + str(tc.data._ecc_point_to_serializable(h))
                        + str(c_expl)
                        + str(tc.data._ecc_point_to_serializable(public_key))
                        + str(tc.data._ecc_point_to_serializable(t1))
                        + str(tc.data._ecc_point_to_serializable(t2))
                        + str(tc.data._ecc_point_to_serializable(t3))
                        + str(tc.data._ecc_point_to_serializable(t_4_1))
                        + str(tc.data._ecc_point_to_serializable(t_4_2))
                        + str(t_hat_expl)
                        + str(tc.data._ecc_point_to_serializable(t_4_3))
                        + str(tc.data._ecc_point_to_serializable(t_4_4))
                    ).encode("UTF8")
                ).hexdigest()
            )
            % self.curve.get_pars().order
        )

        t1_prime_1 = -(c_ver_vect * c_ver_hash)
        t1_prime_2 = self.curve.raise_p(s_1)
        t1_prime = t1_prime_1 + t1_prime_2

        if t1 != t1_prime:
            return 0

        t2v = (c[count - 1]) + -(h * u_prod)

        t2v = t2v * c_ver_hash
        t2v = -t2v + (s_2 * self.curve.get_pars().P)

        if t2 != t2v:
            return 0

        t3_prime_1 = c_ver_tilde * (self.curve.get_pars().order - c_ver_hash)
        t3_prime_prod = ECC.EccPoint(0, 0, "P-256")
        t41v1 = ECC.EccPoint(0, 0, "P-256")
        t41v2 = ECC.EccPoint(0, 0, "P-256")
        t43v1 = ECC.EccPoint(0, 0, "P-256")
        t43v2 = ECC.EccPoint(0, 0, "P-256")
        for i in range(count):
            t3_prime_prod = t3_prime_prod + (
                permutation_commitment["h"][i] * s_prime[i]
            )
            t41v1 = t41v1 + (deserialize_ep(list_1[i][0][0]) * s_prime[i])
            t41v2 = t41v2 + (deserialize_ep(list_0[i][0][0]) * u_ver[i])
            t43v1 = t43v1 + (deserialize_ep(list_1[i][1][0]) * s_prime[i])
            t43v2 = t43v2 + (deserialize_ep(list_0[i][1][0]) * u_ver[i])

        t3_prime_2 = self.curve.raise_p(s_3) + t3_prime_prod
        t3_prime = t3_prime_1 + t3_prime_2

        if t3 != t3_prime:
            return 0

        t41v2 = t41v2 * (self.curve.get_pars().order - c_ver_hash)
        t41v = t41v1 + t41v2
        t41v = t41v + (
            (self.curve.get_pars().order - s_4) * self.curve.get_pars().P
        )

        t43v2 = t43v2 * (self.curve.get_pars().order - c_ver_hash)
        t43v = t43v1 + t43v2
        t43v = t43v + (
            (self.curve.get_pars().order - s_5) * self.curve.get_pars().P
        )

        if t_4_1 != t41v:
            return 0

        if t_4_3 != t43v:
            return 0

        t42v1 = ECC.EccPoint(0, 0, "P-256")
        t42v2 = ECC.EccPoint(0, 0, "P-256")
        t44v1 = ECC.EccPoint(0, 0, "P-256")
        t44v2 = ECC.EccPoint(0, 0, "P-256")

        for i in range(count):
            t42v1 = t42v1 + (deserialize_ep(list_1[i][0][1]) * s_prime[i])
            t42v2 = t42v2 + (deserialize_ep(list_0[i][0][1]) * u_ver[i])
            t44v1 = t44v1 + (deserialize_ep(list_1[i][1][1]) * s_prime[i])
            t44v2 = t44v2 + (deserialize_ep(list_0[i][1][1]) * u_ver[i])
        t42v2 = -(t42v2 * (c_ver_hash))

        t42v = t42v1 + t42v2
        t42v = t42v + -(s_4 * public_key)

        t44v2 = -(t44v2 * (c_ver_hash))
        t44v = t44v1 + t44v2
        t44v = t44v + -((s_5) * public_key)

        if t_4_4 != t44v:
            return 0

        for i in range(count):
            temp = (
                (c[i] * (self.curve.get_pars().order - c_ver_hash))
                + self.curve.raise_p(s_hat[i]),
            )
            if i == 0:
                temp = temp + (h * s_prime[i])
            else:
                temp = temp + (c[i - 1] * s_prime[i])
            if t_hat[i] != temp:
                return 0

        return 1

    def mp_exponentiation(self, list, key, q1):
        """Parallelized list exponentiation.

        Arguments:
                 list   : A list of values
               key (mpz): An exponent

        Returns:
               A list of exponentiated values.
        """
        output = []
        for i in range(len(list)):
            commitment = deserialize_ep(list[i][1]["comm"]) * key
            temp = []
            temp.append(list[i][0])
            temp.append(
                {
                    "v": list[i][1]["v"],
                    "comm": tc.data._ecc_point_to_serializable(commitment),
                }
            )
            output.append(temp)
        q1.put(output)

    def exponentiation_mix(self, list_votes, key):
        """An exponentiation mixnet function.

        Arguments:
           list_votes   : A list of tuples containing values
               key (mpz): An exponent

        Returns:
               A list of values exponentiated by 'key' and a shuffle proof.
        """
        count = len(list_votes)
        list_1 = [[0] * 2] * count
        permutation = gen_permutation(count)

        list_tagged = []
        for i in range(count):
            temp = []
            temp.append(i)
            temp.append(list_votes[i])
            list_tagged.append(temp)

        k, m = divmod(len(list_tagged), multiprocessing.cpu_count())
        split_list = [
            list_tagged[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)]
            for i in range(multiprocessing.cpu_count())
        ]
        processes = [
            multiprocessing.Process(
                target=self.mp_exponentiation, args=(sl, key, q1)
            )
            for sl in split_list
        ]
        for p in processes:
            p.start()
        data = []
        for p in processes:
            data = data + q1.get()

        for p in processes:
            p.join()
            # p.close()

        data.sort()
        for i in range(count):
            temp = []
            temp.append(data[i][1]["v"])
            temp.append(data[i][1]["comm"])
            list_1[permutation[i]] = temp

        pc = PermutationCommitment(self.curve)
        pc.setup(count)
        permutation_commitment = pc.commit(permutation)
        list_vh = list_votes

        for i in range(len(list_vh)):
            if isinstance(list_vh[i]["v"], ECC.EccPoint):
                lvi_1 = tc.data._ecc_point_to_serializable(list_vh[i]["v"])
                lvi_2 = tc.data._ecc_point_to_serializable(list_vh[i]["comm"])

            else:
                lvi_1 = list_vh[i]["v"]
                lvi_2 = list_vh[i]["comm"]

            list_vh[i] = {"v": lvi_1, "comm": lvi_2}
        list_1h = list_1

        for i in range(len(list_1h)):
            if isinstance(list_1h[i][0], ECC.EccPoint):
                list_1h[i][0] = tc.data._ecc_point_to_serializable(
                    list_1h[i][0]
                )
                list_1h[i][1] = tc.data._ecc_point_to_serializable(
                    list_1h[i][1]
                )

        pc_expl = str("")
        for item in permutation_commitment["c"]:
            pc_expl = pc_expl + str(tc.data._ecc_point_to_serializable(item))

        u = [0] * count
        u_prime = [0] * count

        for i in range(count):
            u[i] = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_vh) + str(list_1h) + str(pc_expl) + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                )
                % self.curve.get_pars().order
            )

        for i in range(count):
            u_prime[permutation[i]] = u[i]

        h = self.curve.get_pars().P * self.curve.get_random()

        c = [0] * count
        r = [0] * count
        r_vect = 0
        w_hat = []
        w_prime = []

        for i in range(count):
            r[i] = self.curve.get_random()
            if i == 0:
                c_previous = h
            else:
                c_previous = c[i - 1]
            c[i] = self.curve.raise_p(r[i]) + (c_previous * u_prime[i])
            r_vect = self.curve.add_mod_q(
                r_vect, permutation_commitment["r"][i]
            )
            w_hat.append(self.curve.get_random())
            w_prime.append(self.curve.get_random())

        v = [0] * count
        v[count - 1] = 1

        for i in range(count - 2, -1, -1):
            v[i] = self.curve.mul_mod_q(u_prime[i + 1], v[i + 1])

        r_hat = 0
        r_tilde = 0
        r_prime = 0
        for i in range(count):
            temp = self.curve.mul_mod_q(r[i], v[i])
            r_hat = self.curve.add_mod_q(r_hat, temp)
            temp_tilde = self.curve.mul_mod_q(
                permutation_commitment["r"][i], u[i]
            )
            r_tilde = self.curve.add_mod_q(r_tilde, temp_tilde)
            r_prime = self.curve.add_mod_q(r_prime, u_prime[i])

        w = []
        for i in range(4):
            w.append(self.curve.get_random())

        t1 = self.curve.raise_p(w[0])
        t2 = self.curve.raise_p(w[1])
        t3 = self.curve.raise_p(w[2])
        t_4_1 = ECC.EccPoint(0, 0, self.curve.label)
        t_4_2 = ECC.EccPoint(0, 0, self.curve.label)
        t_hat = [0] * count

        for i in range(count):
            t3 = t3 + (pc.get_generators()[i] * w_prime[i])

            t_4_1 = t_4_1 + (deserialize_ep(list_votes[i]["comm"]) * u[i])
            t_4_2 = t_4_2 + (deserialize_ep(list_1[i][1]) * w_prime[i])
            if i == 0:
                temp = h * w_prime[i]
            else:
                temp = c[i - 1] * w_prime[i]
            t_hat[i] = self.curve.raise_p(w_hat[i]) + temp
        t_4_1 = t_4_1 * w[3]
        t_4_1 = t_4_1 + t_4_2
        t_hat_expl = str("")
        for item in t_hat:
            t_hat_expl = t_hat_expl + str(
                tc.data._ecc_point_to_serializable(item)
            )

        c_expl = str("")
        for item in c:
            c_expl = c_expl + str(tc.data._ecc_point_to_serializable(item))

        c_hash = hashlib.sha256(
            (
                str(list_vh)
                + str(list_1h)
                + str(pc_expl)
                + str(tc.data._ecc_point_to_serializable(h))
                + str(c_expl)
                + str(tc.data._ecc_point_to_serializable(t1))
                + str(tc.data._ecc_point_to_serializable(t2))
                + str(tc.data._ecc_point_to_serializable(t3))
                + str(tc.data._ecc_point_to_serializable(t_4_1))
                + str(t_hat_expl)
            ).encode("UTF-8")
        ).hexdigest()

        c_hash = gmpy2.mpz("0x" + c_hash) % self.curve.get_pars().order

        s_1 = self.curve.add_mod_q(w[0], self.curve.mul_mod_q(c_hash, r_vect))
        s_2 = self.curve.add_mod_q(w[1], self.curve.mul_mod_q(c_hash, r_hat))
        s_3 = self.curve.add_mod_q(w[2], self.curve.mul_mod_q(c_hash, r_tilde))
        s_4 = self.curve.add_mod_q(w[3], self.curve.mul_mod_q(c_hash, key))
        s_hat = [0] * count
        s_prime = [0] * count
        for i in range(count):
            s_hat[i] = self.curve.add_mod_q(
                w_hat[i], self.curve.mul_mod_q(c_hash, r[i])
            )
            s_prime[i] = self.curve.add_mod_q(
                w_prime[i], self.curve.mul_mod_q(c_hash, u_prime[i])
            )
        return (
            list_1,
            permutation_commitment,
            c,
            r,
            t1,
            t2,
            t3,
            t_4_1,
            t_hat,
            h,
            s_1,
            s_2,
            s_3,
            s_4,
            s_hat,
            s_prime,
        )

    def verify_exponentiation_mix(
        self,
        list_0,
        list_1,
        permutation_commitment,
        c,
        r,
        t1,
        t2,
        t3,
        t_4_1,
        t_hat,
        h,
        s_1,
        s_2,
        s_3,
        s_4,
        s_hat,
        s_prime,
    ):
        count = len(list_0)
        if count != len(list_1):
            exit()
        u_ver = [0] * count
        c_prod = ECC.EccPoint(0, 0, self.curve.label)
        h_prod = ECC.EccPoint(0, 0, self.curve.label)
        u_prod = 1
        c_ver_tilde = ECC.EccPoint(0, 0, self.curve.label)
        pc_expl = str("")
        list_vh = list_0

        for i in range(len(list_vh)):
            if isinstance(list_vh[i]["v"], ECC.EccPoint):
                lvi_1 = tc.data._ecc_point_to_serializable(list_vh[i]["v"])
                lvi_2 = tc.data._ecc_point_to_serializable(list_vh[i]["comm"])

            else:
                lvi_1 = list_vh[i]["v"]
                lvi_2 = list_vh[i]["comm"]

            list_vh[i] = {"v": lvi_1, "comm": lvi_2}
        list_1h = list_1

        for i in range(len(list_1h)):
            if isinstance(list_1h[i][0], ECC.EccPoint):
                list_1h[i][0] = tc.data._ecc_point_to_serializable(
                    list_1h[i][0]
                )
                list_1h[i][1] = tc.data._ecc_point_to_serializable(
                    list_1h[i][1]
                )

        for item in permutation_commitment["c"]:
            pc_expl = pc_expl + str(tc.data._ecc_point_to_serializable(item))
        for i in range(count):
            u_ver[i] = (
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_vh) + str(list_1h) + str(pc_expl) + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                )
            ) % self.curve.get_pars().order
            c_prod = c_prod + permutation_commitment["c"][i]
            h_prod = h_prod + permutation_commitment["h"][i]
            u_prod = self.curve.mul_mod_q(u_prod, u_ver[i])
            c_ver_tilde = c_ver_tilde + (
                permutation_commitment["c"][i] * u_ver[i]
            )
        t_hat_expl = str("")
        for item in t_hat:
            t_hat_expl = t_hat_expl + str(
                tc.data._ecc_point_to_serializable(item)
            )

        c_expl = str("")
        for item in c:
            c_expl = c_expl + str(tc.data._ecc_point_to_serializable(item))

        c_ver_vect = c_prod + (-h_prod)
        c_ver_hash = (
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    (
                        str(list_vh)
                        + str(list_1h)
                        + str(pc_expl)
                        + str(tc.data._ecc_point_to_serializable(h))
                        + str(c_expl)
                        + str(tc.data._ecc_point_to_serializable(t1))
                        + str(tc.data._ecc_point_to_serializable(t2))
                        + str(tc.data._ecc_point_to_serializable(t3))
                        + str(tc.data._ecc_point_to_serializable(t_4_1))
                        + str(t_hat_expl)
                    ).encode("UTF8")
                ).hexdigest()
            )
            % self.curve.get_pars().order
        )
        t1_prime_1 = -(c_ver_vect * c_ver_hash)
        t1_prime_2 = self.curve.raise_p(s_1)
        t1_prime = t1_prime_1 + t1_prime_2

        if t1 != t1_prime:
            return 0

        t2v = c[count - 1] + (-(h * u_prod))
        t2v = t2v * c_ver_hash
        t2v = -(t2v)
        t2v = t2v + self.curve.raise_p(s_2)

        if t2 != t2v:
            return 0

        t3_prime_1 = c_ver_tilde * c_ver_hash
        t3_prime_1 = -(t3_prime_1)
        t3_prime_prod = ECC.EccPoint(0, 0, self.curve.label)
        t41v1 = ECC.EccPoint(0, 0, self.curve.label)
        t41v2 = ECC.EccPoint(0, 0, self.curve.label)
        t41v3 = ECC.EccPoint(0, 0, self.curve.label)
        t41v4 = ECC.EccPoint(0, 0, self.curve.label)
        for i in range(count):
            t3_prime_prod = t3_prime_prod + (
                permutation_commitment["h"][i] * s_prime[i]
            )
            t41v1 = t41v1 + (deserialize_ep(list_0[i]["comm"]) * u_ver[i])
            t41v2 = t41v2 + (deserialize_ep(list_1[i][1]) * s_prime[i])
            t41v3 = t41v3 + (deserialize_ep(list_0[i]["comm"]) * u_ver[i])
            t41v4 = t41v4 + deserialize_ep(list_1[i][1])

        t4v = t41v1 * s_4
        t4v = t4v + t41v2
        t4v = t4v + (-(t41v3 * c_ver_hash))
        t4v = t4v + (-(t41v4 * c_ver_hash))

        t3_prime_2 = self.curve.raise_p(s_3) + t3_prime_prod
        t3_prime = t3_prime_1 + t3_prime_2

        if t3 != t3_prime:
            return 0

        for i in range(count):
            temp = -((c[i] * c_ver_hash)) + self.curve.raise_p(s_hat[i])
            if i == 0:
                temp = temp + (h * s_prime[i])
            else:
                temp = temp + (c[i - 1] * s_prime[i])
            if t_hat[i] != temp:
                return 0
        return 1
