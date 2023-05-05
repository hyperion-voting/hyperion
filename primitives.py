import hashlib

from gmpy2 import powmod, mpz, add, mul, f_mod, sub, invert
import threshold_crypto as tc


class PermutationCommitment:
    """Generates a commitment to a permutation matrix.

    Attributes:
        group (Group): The group setup of the protocol.
    """

    def __init__(self, group):
        self.group = group
        self.h = []

    def setup(self, length):
        """
        Args:
            length  (int): Length of the list to be shuffled.
        """
        alpha = self.group.get_random()
        for i in range(length):
            self.h.append(powmod(self.group.g, alpha, self.group.p))

    def commit(self, permutation):
        """
        Args:
            permutation  (mpz): A list representing a permutation.
        
        Returns:
            A commitment to a permutation (c,r).
        """
        if len(permutation) != len(self.h):
            exit()
        r = [0] * len(permutation)
        c = [0] * len(permutation)
        for i in range(len(permutation)):
            r[permutation[i]] = self.group.get_random()
            c[permutation[i]] = powmod(
                self.group.g, r[permutation[i]], self.group.p
            )
            c[permutation[i]] = f_mod(
                mul(c[permutation[i]], self.h[i]), self.group.p
            )
        return {"c": c, "r": r, "h": self.h}

    def get_generators(self):
        """
        Returns:
            The generators used to commit to the permutation list.
        """
        return self.h


class NIZK:
    """Non Interactive Zero Knowledge Proofs of Knowledge

    Attributes:
        group (Group): The group setup of the protocol
    """

    def __init__(self, group):
        """Args:
            group (Group): The group setup of the protocol
        """
        self.group = group

    def prove(self, witness, instance, label):
        """Non malleable Schnorr proof made non-interactive via
        the strong Fiat-Shamir transformation.

        | From: "Fiat A., Shamir A. (1986) How to prove yourself: Practical
        solutions to identification and signature problems."

        Args:
            witness  (mpz): A secret exponent
            instance (mpz): A public key
            label    (str): The identity of a party

        Returns:
            A non interactive proof.
        """
        r = self.group.get_random()
        g_r = powmod(self.group.g, r, self.group.p)
        c = hashlib.sha256(
            (str(self.group.g) + str(instance) + str(g_r) + str(label)).encode(
                "UTF-8"
            )
        ).hexdigest()
        c = mpz("0x" + c)
        z = add(r, mul(c, witness))
        return {"g_r": g_r, "c": c, "z": z}

    def verify(self, proof, instance, label):
        """Verifies a proof generated via NIZK.prove()

        Args:
            proof    (mpz(3)): A proof
            instance    (mpz): A public key
            label       (str): The identity of a party

        Returns:
            1 if proof is a valid proof, 0 otherwise
        """
        c = hashlib.sha256(
            (
                str(self.group.g)
                + str(instance)
                + str(proof["g_r"])
                + str(label)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c)
        lhs = powmod(self.group.g, proof["z"], self.group.p)
        instance_c = powmod(instance, c, self.group.p)
        rhs = f_mod(mul(proof["g_r"], instance_c), self.group.p)
        if lhs == rhs:
            return 1
        else:
            return 0

    def proof_2(self, ciphertext, teller_public_key, voter_public_key, r, r_i):
        """A non interactive proof that a ciphertext encrypts a voter's
        public trapdoor key raised to a random secret exponent.

        | From: "Camenisch J. (1998) Group signature schemes and payment systems
        based on the discrete logarithm problem."

        Args:
            ciphertext     (mpz[2]): A ciphertext
            teller_public_key (mpz): The key used for the encryption of
                                     'ciphertext'
            voter_public_key  (str): A voter's trapdoor public key
            r                 (mpz): The random exponent used for
                                     (El Gamal) encryption
            r_i               (mpz): The random secret exponent

        Returns:
            A non interactive proof.
        """
        r_1, r_2 = self.group.get_random_n(2)
        t_1 = powmod(self.group.g, r_1, self.group.p)
        t_2 = f_mod(
            mul(
                powmod(teller_public_key, r_1, self.group.p),
                powmod(voter_public_key, r_2, self.group.p),
            ),
            self.group.p,
        )
        c = self.group.hash_to_mpz(
            str(self.group.g)
            + str(ciphertext)
            + str(teller_public_key)
            + str(voter_public_key)
            + str(t_1)
            + str(t_2)
        )
        s_1 = f_mod(add(r_1, f_mod(mul(r, c), self.group.q)), self.group.q)
        s_2 = f_mod(add(r_2, f_mod(mul(r_i, c), self.group.q)), self.group.q)
        return {"t_1": t_1, "t_2": t_2, "s_1": s_1, "s_2": s_2}

    def verify_2(self, ciphertext, teller_public_key, voter_public_key, proof):
        """Verifies a proof generated via NIZK.prove_2()

        Args:
            ciphertext     (mpz[2]): A ciphertext
            teller_public_key (mpz): The key used for the encryption of
                                     'ciphertext'
            voter_public_key  (str): A voter's trapdoor public key
            proof          (mpz[4]): A proof

        Returns:
            1 if proof is a valid proof, 0 otherwise
        """
        t_1 = proof["t_1"]
        t_2 = proof["t_2"]
        s_1 = proof["s_1"]
        s_2 = proof["s_2"]
        c = self.group.hash_to_mpz(
            str(self.group.g)
            + str(ciphertext)
            + str(teller_public_key)
            + str(voter_public_key)
            + str(t_1)
            + str(t_2)
        )

        c1 = ciphertext[0]
        c2 = ciphertext[1]

        y_1 = powmod(c1, c, self.group.p)
        y_2 = powmod(c2, c, self.group.p)

        gs_1 = powmod(self.group.g, s_1, self.group.p)
        gs_2 = f_mod(
            mul(
                powmod(teller_public_key, s_1, self.group.p),
                powmod(voter_public_key, s_2, self.group.p),
            ),
            self.group.p,
        )

        lhs_1 = f_mod(mul(y_1, t_1), self.group.p)
        lhs_2 = f_mod(mul(y_2, t_2), self.group.p)

        if lhs_1 == gs_1 and lhs_2 == gs_2:
            return 1
        return 0


class ElGamalEncryption:
    """El Gamal Encryption

    | From: "Elgamal T. (1985) A Public Key Cryptosystem and a Signature
    Scheme Based on Discrete Logarithms."

    Attributes:
        group (Group): The group setup of the protocol
    """

    def __init__(self, group):
        """Args:
            group (Group): The group setup of the protocol
        """
        self.group = group

    def keygen(self):
        """Generates an El Gamal keypair

        Returns:
              x (mpz): A secret key
            g_x (mpz): A public key
        """
        x = self.group.get_random()
        return x, powmod(self.group.g, x, self.group.p)

    def encrypt(self, public_key, message):
        """Encrypts a message

        Args:
            public_key (mpz): A public key
            message    (mpz): A message
            r          (mpz): Randomness
        Returns:
            A ciphertext (mpz[3])
        """
        r = self.group.get_random()
        return (
            powmod(self.group.g, r, self.group.p),
            f_mod(
                mul(powmod(public_key, r, self.group.p), message), self.group.p
            ),
            r,
        )

    def decrypt(self, secret_key, ciphertext):
        """Decrypts a ciphertext

        Args:
            secret_key    (mpz): A secret key
            ciphertext (mpz[2]): A ciphertext

        Returns:
            The original message (mpz)
        """
        c1 = ciphertext[0]
        c2 = ciphertext[1]
        inverse = invert(powmod(c1, secret_key, self.group.p), self.group.p)
        return f_mod(mul(inverse, c2), self.group.p)

    def re_encrypt(self, public_key, ciphertext):
        """Re-encrypts a ciphertext

        Args:
            public_key    (mpz): The public key used to encrypt the
                                original message
            ciphertext (mpz[3]): A ciphertext

        Returns:
            A re-encrypted ciphertext (mpz[3])
        """
        r = self.group.get_random()
        g_r = powmod(self.group.g, r, self.group.p)
        h_r = powmod(public_key, r, self.group.p)
        c0 = f_mod(mul(ciphertext[0], g_r), self.group.p)
        c1 = f_mod(mul(ciphertext[1], h_r), self.group.p)
        r2 = f_mod(add(ciphertext[2], r), self.group.q)
        return c0, c1, r2, r

    def partial_decrypt(self, ciphertext, key_share: tc.KeyShare):
        """Partially decrypts a ciphertext using a threshold key share

        Args:
            key_share     (mpz): A threshold secret key share
            ciphertext (mpz[3]): A ciphertext

        Returns:
            A partially decrypted ciphertext (tc.PartialDecryption)
        """
        v_y = powmod(ciphertext[0], key_share.y, self.group.p)
        return tc.PartialDecryption(key_share.x, v_y)

    def threshold_decrypt(
        self,
        partial_decryptions: [tc.PartialDecryption],
        encrypted_message: tc.EncryptedMessage,
        threshold_params: tc.ThresholdParameters,
        key_params: tc.KeyParameters,
    ):
        """Combines multiple partial decryptions to obtain the original
        message

        | From: tompetersen/threshold-crypto
        """
        partial_indices = [dec.x for dec in partial_decryptions]
        lagrange_coefficients = tc.number.build_lagrange_coefficients(
            partial_indices, key_params.q
        )

        factors = [
            pow(
                partial_decryptions[i].v_y,
                lagrange_coefficients[i],
                key_params.p,
            )
            for i in range(0, len(partial_decryptions))
        ]
        restored_g_ka = tc.number.prod(factors) % key_params.p
        restored_g_minus_ak = tc.number.prime_mod_inv(
            restored_g_ka, key_params.p
        )
        restored_m = encrypted_message.c * restored_g_minus_ak % key_params.p

        return restored_m


class ChaumPedersenProof:
    """Chaum-Pedersen proofs of discrete log equality
    (made non interactive via the strong fiat shamir transform)
    using OR Sigma protocols for the different vote choices

    | From: "Chaum D., Pedersen, T. (1992) Wallet databases
    with observers."

    Attributes:
        group (Group): The group setup of the protocol
    """

    def __init__(self, group):
        """Args:
            group (Group): The group setup of the protocol
        """
        self.group = group

    def prove(self, ciphertext, r, public_key):
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        k = self.group.get_random()
        a = powmod(self.group.g, k, self.group.p)
        b = powmod(public_key, k, self.group.p)
        c = hashlib.sha256(
            (
                str(self.group.g)
                + str(c1)
                + str(public_key)
                + str(c2)
                + str(a)
                + str(b)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c)
        s = sub(k, mul(c, r))
        return c, s

    def mpz_concat(self, mpz_list):
        mpz_concat = ""
        for item in mpz_list:
            mpz_concat = mpz_concat + str(item)
        return mpz_concat

    def hash_concat(self, ul, vl):
        hash_concat = ""
        count = len(ul)
        for i in range(0, count):
            hash_concat = hash_concat + str(ul[i]) + str(vl[i])
        return hash_concat

    def accumulate(self, cl):
        acc = mpz("0x0")
        for c in cl:
            acc = f_mod(add(acc, c), self.group.q)
        return acc

    def prove_or_n(self, ciphertext, r, public_key, n, m, label):
        a = ciphertext["c1"]
        b = ciphertext["c2"]
        h = public_key

        rl = self.group.get_random_n(n)
        cl = self.group.get_random_n(n)
        rnd = self.group.get_random()

        ul = []
        vl = []

        for i in range(0, n):
            if i != m:
                ul.append(
                    f_mod(
                        mul(
                            powmod(self.group.g, rl[i], self.group.p),
                            powmod(
                                invert(a, self.group.p), cl[i], self.group.p
                            ),
                        ),
                        self.group.p,
                    )
                )
                inv = f_mod(
                    mul(
                        b,
                        invert(
                            powmod(self.group.g, i, self.group.p), self.group.p
                        ),
                    ),
                    self.group.p,
                )
                vl.append(
                    f_mod(
                        mul(
                            powmod(h, rl[i], self.group.p),
                            invert(
                                powmod(inv, cl[i], self.group.p), self.group.p
                            ),
                        ),
                        self.group.p,
                    )
                )
            if i == m:
                ul.append(mpz("0x0"))
                vl.append(mpz("0x0"))
        ul[m] = powmod(self.group.g, rnd, self.group.p)
        vl[m] = powmod(h, rnd, self.group.p)
        c = hashlib.sha256(
            (
                str(self.group.g)
                + str(h)
                + str(a)
                + str(b)
                + self.hash_concat(ul, vl)
                + str(label)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c)
        cl[m] = mpz("0x0")
        c_sum = self.accumulate(cl)
        cl[m] = f_mod(sub(c, c_sum), self.group.q)
        rl[m] = f_mod(
            add(rnd, f_mod(mul(cl[m], r), self.group.q)), self.group.q
        )
        return ul, vl, cl, rl

    def verify_or_n(self, ciphertext, h, ul, vl, cl, rl, label):
        a = ciphertext["c1"]
        b = ciphertext["c2"]
        c = hashlib.sha256(
            (
                str(self.group.g)
                + str(h)
                + str(a)
                + str(b)
                + self.hash_concat(ul, vl)
                + str(label)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c)
        if self.accumulate(cl) != c:
            return 0
        for i in range(0, len(rl)):
            if powmod(self.group.g, rl[i], self.group.p) != f_mod(
                mul(ul[i], (powmod(a, cl[i], self.group.p))), self.group.p
            ):
                return 0
            if powmod(h, rl[i], self.group.p) != f_mod(
                mul(
                    vl[i],
                    powmod(
                        f_mod(
                            mul(
                                b,
                                invert(
                                    powmod(self.group.g, i, self.group.p),
                                    self.group.p,
                                ),
                            ),
                            self.group.p,
                        ),
                        cl[i],
                        self.group.p,
                    ),
                ),
                self.group.p,
            ):
                return 0
        return 1

    def verify(self, ciphertext, public_key, c, s):
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        a = f_mod(
            mul(
                powmod(self.group.g, s, self.group.p),
                powmod(c1, c, self.group.p),
            ),
            self.group.p,
        )
        b = f_mod(
            mul(
                powmod(public_key, s, self.group.p),
                powmod(c2, c, self.group.p),
            ),
            self.group.p,
        )
        c_t = hashlib.sha256(
            (
                str(self.group.g)
                + str(c1)
                + str(public_key)
                + str(c2)
                + str(a)
                + str(b)
            ).encode("UTF-8")
        ).hexdigest()
        c_t = mpz("0x" + c_t)
        if c == c_t:
            return 1
        return 0


class DSA:
    """Digital Signature Algorithm

    Attributes:
        group (Group): The group setup of the protocol
    """
    def __init__(self, group):
        self.group = group

    def keygen(self):
        """Generates a DSA keypair.

        Returns:
            r          (mpz): A signing key
            g^r     (mpz[3]): A verification key
        """
        r = self.group.get_random()
        return r, powmod(self.group.g, r, self.group.p)

    def sign(self, signing_key, message):
        """Signs a message.

        Args:
            signing_key (mpz): A signing key
            message     (mpz): A message
            
        Returns:
            A DSA signature (r,s) (mpz[2])
        """
        k = self.group.get_random()
        r = powmod(self.group.g, k, self.group.p)
        hashed_message = hashlib.sha256(
            str(message).encode("UTF-8")
        ).hexdigest()
        hashed_message = mpz("0x" + hashed_message)
        temp = f_mod(
            add(f_mod(mul(signing_key, r), self.group.q), hashed_message),
            self.group.q,
        )
        s = f_mod(mul(temp, invert(k, self.group.q)), self.group.q)
        return r, s

    def verify(self, verification_key, signature, message):
        """Verifies a signature.

        Args:
            verification_key (mpz): A verification key
            signature        (mpz): A signature
            message          (mpz): A signed message

        Returns:
            A DSA signature (r,s) (mpz[2])
        """
        r = signature[0]
        s = signature[1]
        w = invert(s, self.group.q)
        hashed_message = hashlib.sha256(
            str(message).encode("UTF-8")
        ).hexdigest()
        hashed_message = mpz("0x" + hashed_message)
        temp = powmod(self.group.g, mul(hashed_message, w), self.group.p)
        r_t = f_mod(
            mul(temp, powmod(verification_key, mul(r, w), self.group.p)),
            self.group.p,
        )
        if r == r_t:
            return 1
        return 0
