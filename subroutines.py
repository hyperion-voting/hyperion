import random
import time
import hashlib
import multiprocessing

import gmpy2

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
        group (Group): The group setup of the protocol
    """
    def __init__(self, group):
        self.group = group

    def mp_re_encrypt(self, list, public_key, q1):
        """Parallelized list re-encryption.

     Arguments:
              list   : A list of tuples containing two ciphertexts
     public_key (mpz): An El Gamal public key

     Returns:
            A list of re-encrypted ciphertexts.
        """
        ege = ElGamalEncryption(self.group)
        out = []
        for i in range(len(list)):
            index = list[i][0]
            re_encryption = ege.re_encrypt(public_key, list[i][1])
            re_encryption2 = ege.re_encrypt(public_key, list[i][2])
            temp = []
            temp.append(index)
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
            p.close()
        data.sort()
        for i in range(len(data)):
            temp = []
            temp.append(data[i][1])
            temp.append(data[i][3])
            list_1[permutation[i]] = temp
            temp = []
            temp.append(data[i][2])
            temp.append(data[i][4])
            list_r[permutation[i]] = temp
        pc = PermutationCommitment(self.group)
        pc.setup(count)
        permutation_commitment = pc.commit(permutation)
        u = [0] * count
        u_prime = [0] * count
        for i in range(count):
            u[i] = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_votes)
                            + str(list_1)
                            + str(permutation_commitment)
                            + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                ),
                self.group.q,
            )

        for i in range(count):
            u_prime[permutation[i]] = u[i]
        h = gmpy2.powmod(self.group.g, self.group.get_random(), self.group.q)
        c = [0] * count
        r = [0] * count
        r_vect = 0
        w_hat = []
        w_prime = []
        for i in range(count):
            r[i] = self.group.get_random()
            if i == 0:
                c_previous = h
            else:
                c_previous = c[i - 1]
            c[i] = self.group.mul_mod_p(
                self.group.raise_g(r[i]),
                gmpy2.powmod(c_previous, u_prime[i], self.group.p),
            )
            r_vect = self.group.add_mod_q(
                r_vect, permutation_commitment["r"][i]
            )
            w_hat.append(self.group.get_random())
            w_prime.append(self.group.get_random())
        v = [0] * count
        v[count - 1] = 1
        for i in range(count - 2, -1, -1):
            v[i] = self.group.mul_mod_q(u_prime[i + 1], v[i + 1])
        r_hat = 0
        r_tilde = 0
        r_prime = 0
        r_prime_2 = 0
        for i in range(count):
            temp = self.group.mul_mod_q(r[i], v[i])
            r_hat = self.group.add_mod_q(r_hat, temp)
            temp_tilde = self.group.mul_mod_q(
                permutation_commitment["r"][i], u[i]
            )
            r_tilde = self.group.add_mod_q(r_tilde, temp_tilde)
            temp_prime = self.group.mul_mod_q(list_r[i][0], u_prime[i])
            r_prime = self.group.add_mod_q(r_prime, temp_prime)
            temp_prime = self.group.mul_mod_q(list_r[i][1], u_prime[i])
            r_prime_2 = self.group.add_mod_q(r_prime_2, temp_prime)
        w = []
        for i in range(4):
            w.append(self.group.get_random())
        t1 = self.group.raise_g(w[0])
        t2 = self.group.raise_g(w[1])
        t3 = self.group.raise_g(w[2])
        w_4_inv = gmpy2.invert(self.group.raise_g(w[3]), self.group.p)
        t_4_2 = gmpy2.invert(
            gmpy2.powmod(public_key, w[3], self.group.p), self.group.p
        )
        t_4_1 = w_4_inv
        t_4_3 = w_4_inv
        t_4_4 = gmpy2.invert(
            gmpy2.powmod(public_key, w[3], self.group.p), self.group.p
        )
        t_hat = [0] * count
        for i in range(count):
            t3 = gmpy2.f_mod(
                gmpy2.mul(
                    t3,
                    gmpy2.powmod(
                        pc.get_generators()[i], w_prime[i], self.group.p
                    ),
                ),
                self.group.p,
            )
            t_4_1 = gmpy2.f_mod(
                gmpy2.mul(
                    t_4_1,
                    gmpy2.powmod(list_1[i][0][0], w_prime[i], self.group.p),
                ),
                self.group.p,
            )
            t_4_3 = gmpy2.f_mod(
                gmpy2.mul(
                    t_4_3,
                    gmpy2.powmod(list_1[i][1][0], w_prime[i], self.group.p),
                ),
                self.group.p,
            )
            t_4_2 = gmpy2.f_mod(
                gmpy2.mul(
                    t_4_2,
                    gmpy2.powmod(list_1[i][0][1], w_prime[i], self.group.p),
                ),
                self.group.p,
            )
            t_4_4 = gmpy2.f_mod(
                gmpy2.mul(
                    t_4_4,
                    gmpy2.powmod(list_1[i][1][1], w_prime[i], self.group.p),
                ),
                self.group.p,
            )
            if i == 0:
                temp = gmpy2.powmod(h, w_prime[i], self.group.p)
            else:
                temp = gmpy2.powmod(c[i - 1], w_prime[i], self.group.p)
            t_hat[i] = gmpy2.f_mod(
                gmpy2.mul(self.group.raise_g(w_hat[i]), temp), self.group.p
            )
        c_hash = hashlib.sha256(
            (
                str(list_votes)
                + str(list_1)
                + str(permutation_commitment["c"])
                + str(h)
                + str(c)
                + str(public_key)
                + str(t1)
                + str(t2)
                + str(t3)
                + str(t_4_1)
                + str(t_4_2)
                + str(t_hat)
                + str(t_4_3)
                + str(t_4_4)
            ).encode("UTF-8")
        ).hexdigest()
        c_hash = gmpy2.f_mod(gmpy2.mpz("0x" + c_hash), self.group.q)
        s_1 = self.group.add_mod_q(w[0], self.group.mul_mod_q(c_hash, r_vect))
        s_2 = self.group.add_mod_q(w[1], self.group.mul_mod_q(c_hash, r_hat))
        s_3 = self.group.add_mod_q(w[2], self.group.mul_mod_q(c_hash, r_tilde))
        s_4 = self.group.add_mod_q(w[3], self.group.mul_mod_q(c_hash, r_prime))
        s_5 = self.group.add_mod_q(
            w[3], self.group.mul_mod_q(c_hash, r_prime_2)
        )
        s_hat = [0] * count
        s_prime = [0] * count
        for i in range(count):
            s_hat[i] = self.group.add_mod_q(
                w_hat[i], self.group.mul_mod_q(c_hash, r[i])
            )
            s_prime[i] = self.group.add_mod_q(
                w_prime[i], self.group.mul_mod_q(c_hash, u_prime[i])
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
        c_prod = 1
        h_prod = 1
        u_prod = 1
        c_ver_tilde = 1
        for i in range(count):
            u_ver[i] = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_0)
                            + str(list_1)
                            + str(permutation_commitment)
                            + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                ),
                self.group.q,
            )
            c_prod = self.group.mul_mod_p(
                c_prod, permutation_commitment["c"][i]
            )
            h_prod = self.group.mul_mod_p(
                h_prod, permutation_commitment["h"][i]
            )
            u_prod = self.group.mul_mod_q(u_prod, u_ver[i])
            c_ver_tilde = self.group.mul_mod_p(
                c_ver_tilde,
                gmpy2.powmod(
                    permutation_commitment["c"][i], u_ver[i], self.group.p
                ),
            )

        c_ver_vect = gmpy2.divm(c_prod, h_prod, self.group.p)
        c_ver_hash = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    (
                        str(list_0)
                        + str(list_1)
                        + str(permutation_commitment["c"])
                        + str(h)
                        + str(c)
                        + str(public_key)
                        + str(t1)
                        + str(t2)
                        + str(t3)
                        + str(t_4_1)
                        + str(t_4_2)
                        + str(t_hat)
                        + str(t_4_3)
                        + str(t_4_4)
                    ).encode("UTF8")
                ).hexdigest()
            ),
            self.group.q,
        )
        t1_prime_1 = gmpy2.invert(
            gmpy2.powmod(c_ver_vect, c_ver_hash, self.group.p), self.group.p
        )
        t1_prime_2 = self.group.raise_g(s_1)
        t1_prime = gmpy2.f_mod(gmpy2.mul(t1_prime_1, t1_prime_2), self.group.p)

        if t1 != t1_prime:
            return 0

        t2v = gmpy2.divm(
            c[count - 1], gmpy2.powmod(h, u_prod, self.group.p), self.group.p
        )
        t2v = gmpy2.powmod(t2v, c_ver_hash, self.group.p)
        t2v = gmpy2.invert(t2v, self.group.p)
        t2v = gmpy2.f_mod(
            gmpy2.mul(t2v, self.group.raise_g(s_2)), self.group.p
        )

        if t2 != t2v:
            return 0

        t3_prime_1 = gmpy2.powmod(c_ver_tilde, c_ver_hash, self.group.p)
        t3_prime_1 = gmpy2.invert(t3_prime_1, self.group.p)
        t3_prime_prod = 1
        t41v1 = 1
        t41v2 = 1
        t43v1 = 1
        t43v2 = 1
        for i in range(count):
            t3_prime_prod = self.group.mul_mod_p(
                t3_prime_prod,
                gmpy2.powmod(
                    permutation_commitment["h"][i], s_prime[i], self.group.p
                ),
            )
            t41v1 = self.group.mul_mod_p(
                t41v1, gmpy2.powmod(list_1[i][0][0], s_prime[i], self.group.p)
            )
            t41v2 = self.group.mul_mod_p(
                t41v2, gmpy2.powmod(list_0[i][0][0], u_ver[i], self.group.p)
            )
            t43v1 = self.group.mul_mod_p(
                t43v1, gmpy2.powmod(list_1[i][1][0], s_prime[i], self.group.p)
            )
            t43v2 = self.group.mul_mod_p(
                t43v2, gmpy2.powmod(list_0[i][1][0], u_ver[i], self.group.p)
            )

        t3_prime_2 = self.group.mul_mod_p(
            self.group.raise_g(s_3), t3_prime_prod
        )
        t3_prime = self.group.mul_mod_p(t3_prime_1, t3_prime_2)

        if t3 != t3_prime:
            return 0

        t41v2 = gmpy2.invert(
            gmpy2.powmod(t41v2, c_ver_hash, self.group.p), self.group.p
        )
        t41v = self.group.mul_mod_p(t41v1, t41v2)
        t41v = self.group.mul_mod_p(
            t41v, gmpy2.invert(self.group.raise_g(s_4), self.group.p)
        )

        t43v2 = gmpy2.invert(
            gmpy2.powmod(t43v2, c_ver_hash, self.group.p), self.group.p
        )
        t43v = self.group.mul_mod_p(t43v1, t43v2)
        t43v = self.group.mul_mod_p(
            t43v, gmpy2.invert(self.group.raise_g(s_5), self.group.p)
        )

        if t_4_1 != t41v:
            return 0

        if t_4_3 != t43v:
            return 0

        t42v1 = 1
        t42v2 = 1
        t44v1 = 1
        t44v2 = 1

        for i in range(count):
            t42v1 = self.group.mul_mod_p(
                t42v1, gmpy2.powmod(list_1[i][0][1], s_prime[i], self.group.p)
            )
            t42v2 = self.group.mul_mod_p(
                t42v2, gmpy2.powmod(list_0[i][0][1], u_ver[i], self.group.p)
            )
            t44v1 = self.group.mul_mod_p(
                t44v1, gmpy2.powmod(list_1[i][1][1], s_prime[i], self.group.p)
            )
            t44v2 = self.group.mul_mod_p(
                t44v2, gmpy2.powmod(list_0[i][1][1], u_ver[i], self.group.p)
            )
        t42v2 = gmpy2.invert(
            gmpy2.powmod(t42v2, c_ver_hash, self.group.p), self.group.p
        )
        t42v = self.group.mul_mod_p(t42v1, t42v2)
        t42v = self.group.mul_mod_p(
            t42v,
            gmpy2.invert(
                gmpy2.powmod(public_key, s_4, self.group.p), self.group.p
            ),
        )
        t44v2 = gmpy2.invert(
            gmpy2.powmod(t44v2, c_ver_hash, self.group.p), self.group.p
        )
        t44v = self.group.mul_mod_p(t44v1, t44v2)
        t44v = self.group.mul_mod_p(
            t44v,
            gmpy2.invert(
                gmpy2.powmod(public_key, s_5, self.group.p), self.group.p
            ),
        )

        if t_4_2 != t42v:
            return 0

        if t_4_4 != t44v:
            return 0

        for i in range(count):
            temp = self.group.mul_mod_p(
                gmpy2.invert(
                    gmpy2.powmod(c[i], c_ver_hash, self.group.p), self.group.p
                ),
                self.group.raise_g(s_hat[i]),
            )
            if i == 0:
                temp = self.group.mul_mod_p(
                    temp, gmpy2.powmod(h, s_prime[i], self.group.p)
                )
            else:
                temp = self.group.mul_mod_p(
                    temp, gmpy2.powmod(c[i - 1], s_prime[i], self.group.p)
                )
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
            commitment = gmpy2.powmod(list[i][1]["comm"], key, self.group.p)
            temp = []
            temp.append(list[i][0])
            temp.append({"v": list[i][1]["v"], "comm": commitment})
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
            p.close()

        data.sort()
        for i in range(count):
            temp = []
            temp.append(data[i][1]["v"])
            temp.append(data[i][1]["comm"])
            list_1[permutation[i]] = temp

        pc = PermutationCommitment(self.group)
        pc.setup(count)
        permutation_commitment = pc.commit(permutation)

        u = [0] * count
        u_prime = [0] * count

        for i in range(count):
            u[i] = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_votes)
                            + str(list_1)
                            + str(permutation_commitment)
                            + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                ),
                self.group.q,
            )
        for i in range(count):
            u_prime[permutation[i]] = u[i]

        h = gmpy2.powmod(self.group.g, self.group.get_random(), self.group.q)

        c = [0] * count
        r = [0] * count
        r_vect = 0
        w_hat = []
        w_prime = []

        for i in range(count):
            r[i] = self.group.get_random()
            if i == 0:
                c_previous = h
            else:
                c_previous = c[i - 1]
            c[i] = self.group.mul_mod_p(
                self.group.raise_g(r[i]),
                gmpy2.powmod(c_previous, u_prime[i], self.group.p),
            )
            r_vect = self.group.add_mod_q(
                r_vect, permutation_commitment["r"][i]
            )
            w_hat.append(self.group.get_random())
            w_prime.append(self.group.get_random())

        v = [0] * count
        v[count - 1] = 1

        for i in range(count - 2, -1, -1):
            v[i] = self.group.mul_mod_q(u_prime[i + 1], v[i + 1])

        r_hat = 0
        r_tilde = 0
        r_prime = 0
        for i in range(count):
            temp = self.group.mul_mod_q(r[i], v[i])
            r_hat = self.group.add_mod_q(r_hat, temp)
            temp_tilde = self.group.mul_mod_q(
                permutation_commitment["r"][i], u[i]
            )
            r_tilde = self.group.add_mod_q(r_tilde, temp_tilde)
            r_prime = self.group.add_mod_q(r_prime, u_prime[i])

        w = []
        for i in range(4):
            w.append(self.group.get_random())

        t1 = self.group.raise_g(w[0])
        t2 = self.group.raise_g(w[1])
        t3 = self.group.raise_g(w[2])
        t_4_1 = 1
        t_4_2 = 1
        t_hat = [0] * count

        for i in range(count):
            t3 = gmpy2.f_mod(
                gmpy2.mul(
                    t3,
                    gmpy2.powmod(
                        pc.get_generators()[i], w_prime[i], self.group.p
                    ),
                ),
                self.group.p,
            )
            t_4_1 = self.group.mul_mod_p(
                t_4_1, gmpy2.powmod(list_votes[i]["comm"], u[i], self.group.p)
            )
            t_4_2 = self.group.mul_mod_p(
                t_4_2, gmpy2.powmod(list_1[i][1], w_prime[i], self.group.p)
            )
            if i == 0:
                temp = gmpy2.powmod(h, w_prime[i], self.group.p)
            else:
                temp = gmpy2.powmod(c[i - 1], w_prime[i], self.group.p)
            t_hat[i] = gmpy2.f_mod(
                gmpy2.mul(self.group.raise_g(w_hat[i]), temp), self.group.p
            )
        t_4_1 = gmpy2.powmod(t_4_1, w[3], self.group.p)
        t_4_1 = self.group.mul_mod_p(t_4_1, t_4_2)
        c_hash = hashlib.sha256(
            (
                str(list_votes)
                + str(list_1)
                + str(permutation_commitment["c"])
                + str(h)
                + str(c)
                + str(t1)
                + str(t2)
                + str(t3)
                + str(t_4_1)
                + str(t_hat)
            ).encode("UTF-8")
        ).hexdigest()
        c_hash = gmpy2.f_mod(gmpy2.mpz("0x" + c_hash), self.group.q)
        s_1 = self.group.add_mod_q(w[0], self.group.mul_mod_q(c_hash, r_vect))
        s_2 = self.group.add_mod_q(w[1], self.group.mul_mod_q(c_hash, r_hat))
        s_3 = self.group.add_mod_q(w[2], self.group.mul_mod_q(c_hash, r_tilde))
        s_4 = self.group.add_mod_q(w[3], self.group.mul_mod_q(c_hash, key))
        s_hat = [0] * count
        s_prime = [0] * count
        for i in range(count):
            s_hat[i] = self.group.add_mod_q(
                w_hat[i], self.group.mul_mod_q(c_hash, r[i])
            )
            s_prime[i] = self.group.add_mod_q(
                w_prime[i], self.group.mul_mod_q(c_hash, u_prime[i])
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
        c_prod = 1
        h_prod = 1
        u_prod = 1
        c_ver_tilde = 1
        for i in range(count):
            u_ver[i] = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        (
                            str(list_0)
                            + str(list_1)
                            + str(permutation_commitment)
                            + str(i)
                        ).encode("UTF8")
                    ).hexdigest()
                ),
                self.group.q,
            )
            c_prod = self.group.mul_mod_p(
                c_prod, permutation_commitment["c"][i]
            )
            h_prod = self.group.mul_mod_p(
                h_prod, permutation_commitment["h"][i]
            )
            u_prod = self.group.mul_mod_q(u_prod, u_ver[i])
            c_ver_tilde = self.group.mul_mod_p(
                c_ver_tilde,
                gmpy2.powmod(
                    permutation_commitment["c"][i], u_ver[i], self.group.p
                ),
            )

        c_ver_vect = gmpy2.divm(c_prod, h_prod, self.group.p)
        c_ver_hash = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    (
                        str(list_0)
                        + str(list_1)
                        + str(permutation_commitment["c"])
                        + str(h)
                        + str(c)
                        + str(t1)
                        + str(t2)
                        + str(t3)
                        + str(t_4_1)
                        + str(t_hat)
                    ).encode("UTF8")
                ).hexdigest()
            ),
            self.group.q,
        )
        t1_prime_1 = gmpy2.invert(
            gmpy2.powmod(c_ver_vect, c_ver_hash, self.group.p), self.group.p
        )
        t1_prime_2 = self.group.raise_g(s_1)
        t1_prime = gmpy2.f_mod(gmpy2.mul(t1_prime_1, t1_prime_2), self.group.p)

        if t1 != t1_prime:
            return 0

        t2v = gmpy2.divm(
            c[count - 1], gmpy2.powmod(h, u_prod, self.group.p), self.group.p
        )
        t2v = gmpy2.powmod(t2v, c_ver_hash, self.group.p)
        t2v = gmpy2.invert(t2v, self.group.p)
        t2v = gmpy2.f_mod(
            gmpy2.mul(t2v, self.group.raise_g(s_2)), self.group.p
        )

        if t2 != t2v:
            return 0

        t3_prime_1 = gmpy2.powmod(c_ver_tilde, c_ver_hash, self.group.p)
        t3_prime_1 = gmpy2.invert(t3_prime_1, self.group.p)
        t3_prime_prod = 1
        t41v1 = 1
        t41v2 = 1
        t41v3 = 1
        t41v4 = 1
        for i in range(count):
            t3_prime_prod = self.group.mul_mod_p(
                t3_prime_prod,
                gmpy2.powmod(
                    permutation_commitment["h"][i], s_prime[i], self.group.p
                ),
            )
            t41v1 = self.group.mul_mod_p(
                t41v1, gmpy2.powmod(list_0[i]["comm"], u_ver[i], self.group.p)
            )
            t41v2 = self.group.mul_mod_p(
                t41v1, gmpy2.powmod(list_1[i][1], s_prime[i], self.group.p)
            )
            t41v3 = self.group.mul_mod_p(
                t41v3, gmpy2.powmod(list_0[i]["comm"], u_ver[i], self.group.p)
            )
            t41v4 = self.group.mul_mod_p(t41v4, list_1[i][1])

        t4v = gmpy2.powmod(t41v1, s_4, self.group.p)
        t4v = self.group.mul_mod_p(t4v, t41v2)
        t4v = self.group.mul_mod_p(
            t4v,
            gmpy2.invert(
                gmpy2.powmod(t41v3, c_ver_hash, self.group.p), self.group.p
            ),
        )
        t4v = self.group.mul_mod_p(
            t4v,
            gmpy2.invert(
                gmpy2.powmod(t41v4, c_ver_hash, self.group.p), self.group.p
            ),
        )

        t3_prime_2 = self.group.mul_mod_p(
            self.group.raise_g(s_3), t3_prime_prod
        )
        t3_prime = self.group.mul_mod_p(t3_prime_1, t3_prime_2)

        if t3 != t3_prime:
            return 0

        if t_4_1 != t4v:
            return 0

        for i in range(count):
            temp = self.group.mul_mod_p(
                gmpy2.invert(
                    gmpy2.powmod(c[i], c_ver_hash, self.group.p), self.group.p
                ),
                self.group.raise_g(s_hat[i]),
            )
            if i == 0:
                temp = self.group.mul_mod_p(
                    temp, gmpy2.powmod(h, s_prime[i], self.group.p)
                )
            else:
                temp = self.group.mul_mod_p(
                    temp, gmpy2.powmod(c[i - 1], s_prime[i], self.group.p)
                )
            if t_hat[i] != temp:
                return 0
        return 1
