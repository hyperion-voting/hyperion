import hashlib

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS

from util import deserialize_ep, deserialize_pd

from gmpy2 import powmod, mpz, add, mul, f_mod, sub, invert
import threshold_crypto as tc


class PermutationCommitment:
    """Generates a commitment to a permutation matrix.

    Attributes:
        curve (curve): The curve setup of the protocol.
    """

    def __init__(self, curve):
        self.curve = curve
        self.h = []

    def setup(self, length):
        """
        Args:
            length  (int): Length of the list to be shuffled.
        """
        alpha = self.curve.get_random()
        for i in range(length):
            self.h.append((self.curve.get_pars().P * alpha))

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
            r[permutation[i]] = self.curve.get_random()
            c[permutation[i]] = self.curve.get_pars().P * r[permutation[i]]
            c[permutation[i]] = c[permutation[i]] + self.h[i]
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
        curve (curve): The curve setup of the protocol
    """

    def __init__(self, curve):
        """Args:
        curve (curve): The curve setup of the protocol
        """
        self.curve = curve

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
        r = self.curve.get_random()
        gr = r * self.curve.get_pars().P
        c = hashlib.sha256(
            (
                str(self.curve.get_pars().P.x)
                + str(self.curve.get_pars().P.x)
                + str(instance)
                + str(gr)
                + str(label)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c) % self.curve.get_pars().order
        z = (r + c * witness) % self.curve.get_pars().order
        return {"gr": gr, "c": c, "z": z}

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
                str(self.curve.get_pars().P.x)
                + str(self.curve.get_pars().P.x)
                + str(instance)
                + str(proof["gr"])
                + str(label)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c) % self.curve.get_pars().order
        lhs = proof["z"] * self.curve.get_pars().P
        instance_c = c * instance
        rhs = proof["gr"] + instance_c
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
        r_1, r_2 = self.curve.get_random_n(2)
        t_1 = r_1 * self.curve.get_pars().P
        t_2 = (r_1 * teller_public_key) + (r_2 * voter_public_key)
        c = self.curve.hash_to_mpz(
            str(self.curve.get_pars().P.x)
            + str(self.curve.get_pars().P.x)
            + str(ciphertext[0].x)
            + str(ciphertext[0].y)
            + str(ciphertext[1].x)
            + str(ciphertext[1].y)
            + str(ciphertext[2])
            + str(teller_public_key.x)
            + str(teller_public_key.y)
            + str(voter_public_key.x)
            + str(voter_public_key.y)
            + str(t_1.x)
            + str(t_1.y)
            + str(t_2.x)
            + str(t_2.y)
        )

        s_1 = (r_1 + (r * c)) % self.curve.get_pars().order
        s_2 = (r_2 + (r_i * c)) % self.curve.get_pars().order
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
        c = self.curve.hash_to_mpz(
            str(self.curve.get_pars().P.x)
            + str(self.curve.get_pars().P.x)
            + str(ciphertext[0].x)
            + str(ciphertext[0].y)
            + str(ciphertext[1].x)
            + str(ciphertext[1].y)
            + str(ciphertext[2])
            + str(teller_public_key.x)
            + str(teller_public_key.y)
            + str(voter_public_key.x)
            + str(voter_public_key.y)
            + str(t_1.x)
            + str(t_1.y)
            + str(t_2.x)
            + str(t_2.y)
        )

        c1 = ciphertext[0]
        c2 = ciphertext[1]

        y_1 = c * c1
        y_2 = c * c2

        gs_1 = self.curve.get_pars().P * s_1
        gs_2 = (s_1 * teller_public_key) + (s_2 * voter_public_key)

        lhs_1 = y_1 + t_1
        lhs_2 = y_2 + t_2

        if lhs_1 == gs_1 and lhs_2 == gs_2:
            return 1
        return 0


class ElGamalEncryption:
    """El Gamal Encryption

    | From: "Elgamal T. (1985) A Public Key Cryptosystem and a Signature
    Scheme Based on Discrete Logarithms."

    Attributes:
        curve (Curve): The curve to be used by the protocol
    """

    def __init__(self, curve):
        """Args:
        curve (Curve): The curve to be used by the protocol
        """
        self.curve = curve

    def keygen(self):
        """Generates an El Gamal keypair

        Returns:
              x (mpz): A secret key
            g_x (mpz): A public key
        """
        x = self.curve.get_random()
        return x, x * self.curve.get_pars().P

    def encrypt(self, public_key, message):
        """Encrypts a message

        Args:
            public_key (mpz): A public key
            message    (mpz): A message
            r          (mpz): Randomness
        Returns:
            A ciphertext (mpz[3])
        """
        r = self.curve.get_random()
        return [
            r * self.curve.get_pars().P,
            (r * public_key) + (message),
            r,
        ]

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
        s = (self.curve.get_pars().order + -secret_key) * c1
        return c2 + s

    def re_encrypt(self, public_key, ciphertext):
        """Re-encrypts a ciphertext

        Args:
            public_key    (mpz): The public key used to encrypt the
                                original message
            ciphertext (mpz[3]): A ciphertext

        Returns:
            A re-encrypted ciphertext (mpz[3])
        """
        r = self.curve.get_random()
        gr = r * self.curve.get_pars().P
        hr = r * public_key
        c0 = ciphertext[0] + gr
        c1 = ciphertext[1] + hr
        r2 = ciphertext[2] + r
        return [c0, c1, r2, r]

    def partial_decrypt(self, ciphertext, key_share: tc.KeyShare):
        """Partially decrypts a ciphertext using a threshold key share

        Args:
            key_share     (mpz): A threshold secret key share
            ciphertext (mpz[3]): A ciphertext

        Returns:
            A partially decrypted ciphertext (tc.PartialDecryption)
        """

        v_y = ciphertext * key_share.y
        return tc.PartialDecryption(key_share.x, v_y, self.curve.get_pars())

    def threshold_decrypt(
        self,
        partial_decryptions: [tc.PartialDecryption],
        encrypted_message: tc.EncryptedMessage,
        threshold_params: tc.ThresholdParameters,
    ):
        """Combines multiple partial decryptions to obtain the original
        message

        | From: tompetersen/threshold-crypto
        """
        # partial_indices = [dec.x for dec in partial_decryptions]
        # lagrange_coefficients = tc.number.build_lagrange_coefficients(
        # partial_indices, key_params.q
        # )

        # factors = [
        # pow(
        # partial_decryptions[i].v_y,
        # lagrange_coefficients[i],
        # key_params.p,
        # )
        # for i in range(0, len(partial_decryptions))
        # ]
        # restored_g_ka = tc.number.prod(factors) % key_params.p
        # restored_g_minus_ak = tc.number.prime_mod_inv(
        # restored_g_ka, key_params.p
        # )
        # restored_m = encrypted_message.c * restored_g_minus_ak % key_params.p
        partial_decryptions[0] = deserialize_pd(
            self.curve.get_pars(), partial_decryptions[0]
        )
        curve_params = partial_decryptions[0].curve_params
        for i in range(1, len(partial_decryptions)):
            partial_decryptions[i] = deserialize_pd(
                self.curve.get_pars(), partial_decryptions[i]
            )
            if partial_decryptions[i].curve_params != curve_params:
                raise ThresholdCryptoError(
                    "Varying curve parameters found in partial re-encryption keys"
                )

        partial_indices = [dec.x for dec in partial_decryptions]
        lagrange_coefficients = [
            tc.lagrange_coefficient_for_key_share_indices(
                partial_indices, idx, curve_params
            )
            for idx in partial_indices
        ]

        summands = [
            lagrange_coefficients[i].coefficient * partial_decryptions[i].yC1
            for i in range(0, len(partial_decryptions))
        ]
        restored_kdP = tc.number.ecc_sum(summands)

        restored_point = encrypted_message.C2 + (-restored_kdP)

        return restored_point


class ChaumPedersenProof:
    """Chaum-Pedersen proofs of discrete log equality
    (made non interactive via the strong fiat shamir transform)
    using OR Sigma protocols for the different vote choices

    | From: "Chaum D., Pedersen, T. (1992) Wallet databases
    with observers."

    Attributes:
        curve (curve): The curve setup of the protocol
    """

    def __init__(self, curve):
        """Args:
        curve (curve): The curve setup of the protocol
        """
        self.curve = curve

    def prove(self, ciphertext, r, public_key):
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        k = self.curve.get_random()
        a = k * self.curve.get_pars().P
        b = k * public_key
        c = hashlib.sha256(
            (
                str(self.curve.get_pars().P.x)
                + str(self.curve.get_pars().P.y)
                + str(c1.x)
                + str(c1.y)
                + str(public_key.x)
                + str(public_key.y)
                + str(c2.x)
                + str(c2.y)
                + str(a.x)
                + str(a.y)
                + str(b.x)
                + str(b.y)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c) % self.curve.get_pars().order
        s = k + (
            self.curve.get_pars().order
            - ((c * r) % self.curve.get_pars().order)
        )
        s = s % self.curve.get_pars().order
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
            acc = acc + c
        return acc

    def prove_or_n(self, ciphertext, r, public_key, n, m, label):
        a = ciphertext["c1"]
        b = ciphertext["c2"]
        h = public_key

        rl = self.curve.get_random_n(n)
        cl = self.curve.get_random_n(n)
        rnd = self.curve.get_random()

        ul = []
        vl = []

        for i in range(0, n):
            if i != m:
                ul.append(
                    (rl[i] * self.curve.get_pars().P)
                    + ((a * (self.curve.get_pars().order - cl[i])))
                )

                inv = b + (
                    (self.curve.get_pars().order - i) * self.curve.get_pars().P
                )
                vl.append(
                    (h * rl[i]) + (inv * (self.curve.get_pars().order - cl[i]))
                )
            if i == m:
                ul.append(mpz("0x0"))
                vl.append(mpz("0x0"))
        ul[m] = rnd * self.curve.get_pars().P
        vl[m] = rnd * h
        c = hashlib.sha256(
            (
                str(self.curve.get_pars().P.x)
                + str(self.curve.get_pars().P.y)
                + str(h.x)
                + str(h.y)
                + str(a.x)
                + str(a.y)
                + str(b.x)
                + str(b.y)
                + self.hash_concat(ul, vl)
                + str(label)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c) % self.curve.get_pars().order
        cl[m] = mpz("0x0")
        c_sum = self.accumulate(cl) % self.curve.get_pars().order
        cl[m] = (c - c_sum) % self.curve.get_pars().order
        rl[m] = (rnd + (cl[m] * r)) % self.curve.get_pars().order
        return [ul, vl, cl, rl]

    def verify_or_n(self, ciphertext, h, ul, vl, cl, rl, label):
        a = ciphertext["c1"]
        b = ciphertext["c2"]
        c = hashlib.sha256(
            (
                str(self.curve.get_pars().P.x)
                + str(self.curve.get_pars().P.y)
                + str(h.x)
                + str(h.y)
                + str(a.x)
                + str(a.y)
                + str(b.x)
                + str(b.y)
                + self.hash_concat(ul, vl)
                + str(label)
            ).encode("UTF-8")
        ).hexdigest()
        c = mpz("0x" + c) % self.curve.get_pars().order
        if self.accumulate(cl) % self.curve.get_pars().order != c:
            return 0
        for i in range(0, len(rl)):
            if (rl[i] * self.curve.get_pars().P) != (ul[i] + (a * cl[i])):
                return 0
            if (h * rl[i]) != (
                vl[i]
                + (
                    (
                        b
                        + (
                            (self.curve.get_pars().order - i)
                            * self.curve.get_pars().P
                        )
                    )
                    * cl[i]
                )
            ):
                return 0
        return 1

    def verify(self, ciphertext, public_key, c, s):
        c1 = ciphertext["c1"]
        c2 = ciphertext["c2"]
        a = (s * self.curve.get_pars().P) + (c1 * c)
        b = (s * public_key) + (c2 * c)
        c_t = hashlib.sha256(
            (
                str(self.curve.get_pars().P.x)
                + str(self.curve.get_pars().P.y)
                + str(c1.x)
                + str(c1.y)
                + str(public_key.x)
                + str(public_key.y)
                + str(c2.x)
                + str(c2.y)
                + str(a.x)
                + str(a.y)
                + str(b.x)
                + str(b.y)
            ).encode("UTF-8")
        ).hexdigest()
        c_t = mpz("0x" + c_t) % self.curve.get_pars().order
        if c == c_t:
            return 1
        return 0


class DSA:
    """Digital Signature Algorithm

    Attributes:
        curve (curve): The curve setup of the protocol
    """

    def __init__(self, curve):
        self.curve = curve

    def keygen(self):
        """Generates a DSA keypair.

        Returns:
            r          (mpz): A signing key
            g^r     (mpz[3]): A verification key
        """
        key = ECC.generate(curve="P-256")
        return key, key.public_key()

    def sign(self, signing_key, message):
        """Signs a message.

        Args:
            signing_key (mpz): A signing key
            message     (mpz): A message

        Returns:
            A DSA signature (r,s) (mpz[2])
        """
        h = SHA256.new(str(message).encode("UTF-8"))
        signer = DSS.new(signing_key, "fips-186-3")
        signature = signer.sign(h)
        return signature

    def verify(self, verification_key, signature, message):
        """Verifies a signature.

        Args:
            verification_key (mpz): A verification key
            signature        (mpz): A signature
            message          (mpz): A signed message

        Returns:
            A DSA signature (r,s) (mpz[2])
        """
        h = SHA256.new(str(message).encode("UTF-8"))
        verifier = DSS.new(verification_key, "fips-186-3")
        try:
            verifier.verify(h, signature)
            return 1
        except ValueError:
            return 0
