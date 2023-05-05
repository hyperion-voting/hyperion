import multiprocessing
import hashlib
import random

import threshold_crypto as tc
import gmpy2

from group import pars_2048
from primitives import DSA, ElGamalEncryption, NIZK, ChaumPedersenProof
from exceptions import (
    InvalidSignatureException,
    InvalidProofException,
    InvalidWFNProofException,
)
from subroutines import Mixnet


class Voter:
    def __init__(self, group, id, vote_min, vote_max):
        self.id = id
        self.vote_min = vote_min
        self.vote_max = vote_max
        self.group = group

    def choose_vote_value(self):
        self.vote = random.randrange(self.vote_min, self.vote_max)

    def generate_dsa_keys(self):
        dsa = DSA(self.group)
        self.secret_key, self.public_key = dsa.keygen()

    def generate_trapdoor_keypair(self):
        self.ege = ElGamalEncryption(self.group)
        self.secret_trapdoor_key, self.public_trapdoor_key = self.ege.keygen()

    def generate_pok_trapdoor_keypair(self):
        nizk = NIZK(self.group)
        self.pok_trapdoor_key = nizk.prove(
            self.secret_trapdoor_key, self.public_trapdoor_key, self.id
        )

    def encrypt_vote(self, teller_public_key):
        self.g_vote = self.group.raise_g(int(self.vote))
        self.encrypted_vote = self.ege.encrypt(
            teller_public_key.g_a, self.g_vote
        )

    def generate_wellformedness_proof(self, teller_public_key):
        encrypted_vote = {
            "c1": self.encrypted_vote[0],
            "c2": self.encrypted_vote[1],
        }
        r = self.encrypted_vote[2]
        chmp = ChaumPedersenProof(self.group)
        self.wellformedness_proof = chmp.prove_or_n(
            encrypted_vote,
            r,
            teller_public_key.g_a,
            self.vote_max,
            int(self.vote),
            self.id,
        )

    def sign_ballot(self):
        self.dsa = DSA(self.group)
        hash = self.group.hash_to_mpz(
            str(self.encrypted_vote)
            + str(self.public_trapdoor_key)
            + str(self.pok_trapdoor_key)
            + str(self.wellformedness_proof)
        )
        self.signature = self.dsa.sign(self.secret_key, hash)
        bb_data = {
            "id": self.id,
            "spk": self.public_key,
            "sig": self.signature,
            # only for poc
            "stk": self.secret_trapdoor_key,
            "ev": self.encrypted_vote,
            "ptk": self.public_trapdoor_key,
            "pi_1": self.pok_trapdoor_key,
            "pi_2": self.wellformedness_proof,
        }
        return bb_data

    def notify(self, encrypted_term):
        self.g_ri = encrypted_term

    def generate_verification_comm(self):
        g_ri_x = gmpy2.powmod(
            self.g_ri, self.secret_trapdoor_key, self.group.p
        )
        return g_ri_x


class Teller:
    def __init__(self, group, secret_key_share, public_key):
        self.group = group
        self.secret_key_share = secret_key_share
        self.public_key = public_key
        self.ege = ElGamalEncryption(self.group)
        self.core_count = multiprocessing.cpu_count()

    def generate_threshold_keys(k, num_tellers, tc_key_params):
        thresh_params = tc.ThresholdParameters(k, num_tellers)
        pub_key, key_shares = tc.create_public_key_and_shares_centralized(
            tc_key_params, thresh_params
        )
        return pub_key, key_shares

    def mp_raise_h(self, list_in, q1, q2, q3):
        teller_proofs = []
        teller_registry = []
        list_out = []
        for i in range(0, len(list_in)):
            ballot = list_in[i][1]
            index = list_in[i][0]
            ciphertext, proof, r_i = self.raise_h(self.public_key, ballot)
            teller_proof_record = {
                "h_r": ciphertext,
                "proof": proof,
                "ptk": ballot["ptk"],
                "id": ballot["id"],
            }
            teller_proofs.append(teller_proof_record)
            ballot["h_r"] = ciphertext
            ballot["proof_h_r"] = proof
            teller_registry.append(
                {
                    "id": ballot["id"],
                    "g_r": self.group.raise_g(r_i),
                    "ptk": ballot["ptk"],
                }
            )
            temp = []
            temp.append(index)
            temp.append(ballot)
            list_out.append(temp)
        q1.put(teller_proofs)
        q2.put(teller_registry)
        q3.put(list_out)

    def ciphertext_list_split(self, list_0, n):
        k, m = divmod(len(list_0), n)
        split_list = [
            list_0[i * k + min(i, m) : (i + 1) * k + min(i + 1, m)]
            for i in range(n)
        ]
        return split_list

    def tag_ciphertexts(self, list_0):
        list_1 = []
        index = 0
        for item in list_0:
            temp = []
            temp.append(index)
            temp.append(item[0])
            temp.append(item[1])
            list_1.append(temp)
            index = index + 1
        return list_1

    def verify_decryption_proof(
        self,
        tau,
        p_1,
        p_2,
        w,
        public_key_share,
        ciphertexts,
        partial_decryptions,
    ):
        prod_alpha = 1
        prod_partial_decryptions = 1
        alpha_terms = []
        for ciphertext in ciphertexts:
            index = ciphertext[0]
            alpha_terms.append(ciphertext[1][0])
            t = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(
                            str(tau) + str(ciphertext[1][0]) + str(index)
                        ).encode("UTF-8")
                    ).hexdigest()
                ),
                self.group.q,
            )
            s_2 = gmpy2.powmod(ciphertexts[1][0], t, self.group.p)
            prod_alpha = gmpy2.f_mod(gmpy2.mul(prod_alpha, s_2), self.group.p)

        for partial_decryption in partial_decryptions:
            prod_partial_decryptions = self.group.mul_mod_p(
                prod_partial_decryptions, partial_decryption.v_y
            )
        u = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1)
                        + str(p_1)
                        + str(self.group.g)
                        + str(public_key_share)
                        + str(alpha_terms)
                        + str(partial_decryptions)
                    ).encode("UTF-8")
                ).hexdigest()
            ),
            self.group.q,
        )
        v_1 = self.group.mul_mod_p(
            self.group.raise_g(w),
            gmpy2.powmod(public_key_share, u, self.group.p),
        )
        v_2 = gmpy2.powmod(prod_alpha, w, self.group.p)
        v_2 = self.group.mul_mod_p(
            v_2, gmpy2.powmod(prod_partial_decryptions, u, self.group.p)
        )
        if (p_1 == v_1) and (p_2 == v_2):
            return 1
        return 0

    def mp_partial_decrypt(self, ciphertexts_in, q1, q2, q3):
        tau_1 = self.group.get_random()
        tau_2 = self.group.get_random()
        r_1 = self.group.get_random()
        r_2 = self.group.get_random()
        p_1_1 = self.group.raise_g(r_1)
        p_2_1 = self.group.raise_g(r_2)
        comm_tau_1 = hashlib.sha256(str(tau_1).encode("UTF-8")).hexdigest()
        comm_tau_2 = hashlib.sha256(str(tau_2).encode("UTF-8")).hexdigest()
        output = []
        output2 = []
        proof = []
        prod_alpha_1 = 1
        prod_alpha_2 = 1
        alpha_terms_1 = []
        alpha_terms_2 = []
        for ciphertext in ciphertexts_in:
            index = ciphertext[0]
            alpha_1 = ciphertext[1][0]
            alpha_2 = ciphertext[2][0]
            t_1 = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau_1) + str(alpha_1) + str(index)).encode(
                            "UTF-8"
                        )
                    ).hexdigest()
                ),
                self.group.q,
            )
            t_2 = gmpy2.f_mod(
                gmpy2.mpz(
                    "0x"
                    + hashlib.sha256(
                        str(str(tau_2) + str(alpha_2) + str(index)).encode(
                            "UTF-8"
                        )
                    ).hexdigest()
                ),
                self.group.q,
            )
            pd_1 = self.ege.partial_decrypt(
                ciphertext[1], self.secret_key_share
            )
            pd_2 = self.ege.partial_decrypt(
                ciphertext[2], self.secret_key_share
            )
            prod_alpha_1 = self.group.mul_mod_p(
                prod_alpha_1, gmpy2.powmod(alpha_1, t_1, self.group.p)
            )
            prod_alpha_2 = self.group.mul_mod_p(
                prod_alpha_2, gmpy2.powmod(alpha_2, t_2, self.group.p)
            )
            alpha_terms_1.append(alpha_1)
            alpha_terms_2.append(alpha_2)
            temp = []

            temp.append(index)
            temp.append(pd_1)

            output.append(temp)
            temp2 = []
            temp2.append(index)
            temp2.append(pd_2)
            output2.append(temp2)
        q1.put(output)
        q2.put(output2)
        p_1_2 = gmpy2.powmod(prod_alpha_1, r_1, self.group.p)
        p_2_2 = gmpy2.powmod(prod_alpha_2, r_2, self.group.p)
        u_1 = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_1_1)
                        + str(p_1_2)
                        + str(self.group.g)
                        + str(self.group.raise_g(self.secret_key_share.y))
                        + str(alpha_terms_1)
                        + str(output)
                    ).encode("UTF-8")
                ).hexdigest()
            ),
            self.group.q,
        )
        u_2 = gmpy2.f_mod(
            gmpy2.mpz(
                "0x"
                + hashlib.sha256(
                    str(
                        str(p_2_1)
                        + str(p_2_2)
                        + str(self.group.g)
                        + str(self.group.raise_g(self.secret_key_share.y))
                        + str(alpha_terms_2)
                        + str(output2)
                    ).encode("UTF-8")
                ).hexdigest()
            ),
            self.group.q,
        )
        w_1 = self.group.sub_mod_q(
            r_1, self.group.mul_mod_q(u_1, self.secret_key_share.y)
        )
        w_2 = self.group.sub_mod_q(
            r_2, self.group.mul_mod_q(u_2, self.secret_key_share.y)
        )
        q3.put(
            {
                "p_1_1": p_1_1,
                "p_1_2": p_1_2,
                "p_2_1": p_2_1,
                "p_2_2": p_2_2,
                "w_1": w_1,
                "w_2": w_2,
                "tau_1": tau_1,
                "tau_2": tau_2,
            }
        )

    def multi_dim_index(self, list, key):
        for item in list:
            if item[0] == key:
                return item
        return None

    def mp_full_decrypt(self, pd1_in, ciphertexts, col, q1):
        result = []
        for item in pd1_in:
            index = item[0]
            ct = self.multi_dim_index(ciphertexts, index)
            ciphertext = tc.EncryptedMessage(ct[col][0], ct[col][1], "")
            result.append(
                [
                    index,
                    self.ege.threshold_decrypt(
                        item[1],
                        ciphertext,
                        tc.ThresholdParameters(2, 3),
                        pars_2048(),
                    ),
                ]
            )
        q1.put(result)

    def full_decrypt(self, pd_in, q1):
        global decrypted
        split_ciphertexts = self.ciphertext_list_split(pd_in, self.core_count)
        processes = [
            multiprocessing.Process(
                target=self.mp_full_decrypt, args=(ciph, q1)
            )
            for ciph in split_ciphertexts
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
        decrypted = data

    def validate_ballot(group, teller_public_key, ballot):
        dsa = DSA(group)
        hash = group.hash_to_mpz(
            str(ballot["ev"])
            + str(ballot["ptk"])
            + str(ballot["pi_1"])
            + str(ballot["pi_2"])
        )
        nizk = NIZK(group)
        chmp = ChaumPedersenProof(group)
        try:
            if not dsa.verify(ballot["spk"], ballot["sig"], hash):
                raise InvalidSignatureException(ballot["id"])
            if not nizk.verify(ballot["pi_1"], ballot["ptk"], ballot["id"]):
                raise InvalidProofException(ballot["id"])
            ciphertext = {"c1": ballot["ev"][0], "c2": ballot["ev"][1]}
            if not chmp.verify_or_n(
                ciphertext,
                teller_public_key.g_a,
                ballot["pi_2"][0],
                ballot["pi_2"][1],
                ballot["pi_2"][2],
                ballot["pi_2"][3],
                ballot["id"],
            ):
                raise InvalidWFNProofException(ballot["id"])
        except Exception as e:
            print(e)

    def raise_h(self, teller_public_key, ballot):
        r_i = self.group.get_random()
        voter_public_key = ballot["ptk"]
        message = gmpy2.powmod(voter_public_key, r_i, self.group.p)
        ege = ElGamalEncryption(self.group)
        ciphertext = ege.encrypt(teller_public_key.g_a, message)
        nizk = NIZK(self.group)
        proof = nizk.proof_2(
            ciphertext,
            teller_public_key.g_a,
            voter_public_key,
            ciphertext[2],
            r_i,
        )
        return ciphertext, proof, r_i

    def verify_proof_h_r(group, teller_public_key, h_r, ptk, proof, id):
        nizk = NIZK(group)
        if not nizk.verify_2(h_r, teller_public_key.g_a, ptk, proof):
            raise InvalidProofException(id)
            print(e)

    def rencryption_mix(self, list_0):
        mx = Mixnet(self.group)
        proof = mx.re_encryption_mix(list_0, self.public_key.g_a)
        return proof

    def verify_re_enc_mix(self, list_0, proof):
        mx = Mixnet(self.group)
        return mx.verify_mix(
            self.public_key.g_a,
            list_0,
            proof[0],
            proof[1],
            proof[2],
            proof[3],
            proof[4],
            proof[5],
            proof[6],
            proof[7],
            proof[8],
            proof[9],
            proof[10],
            proof[11],
            proof[12],
            proof[13],
            proof[14],
            proof[15],
            proof[16],
            proof[17],
            proof[18],
            proof[19],
        )

    def notify(group, registry_entry):
        ege = ElGamalEncryption(group)
        g_ri = group.raise_g(registry_entry["r_i"])
        ciphertext = ege.encrypt(registry_entry["ptk"], g_ri)
        return ciphertext

    def decrypt(group, registry_entry):
        ege = ElGamalEncryption(group)
        g_ri = group.raise_g(registry_entry["r_i"])
        ciphertext = ege.encrypt(registry_entry["ptk"], g_ri)
        return ciphertext

    def individual_board_shuffle(self, list_0):
        key = self.group.get_random()
        mx = Mixnet(self.group)
        proof = mx.exponentiation_mix(list_0, key)
        mx.verify_exponentiation_mix(
            list_0,
            proof[0],
            proof[1],
            proof[2],
            proof[3],
            proof[4],
            proof[5],
            proof[6],
            proof[7],
            proof[8],
            proof[9],
            proof[10],
            proof[11],
            proof[12],
            proof[13],
            proof[14],
            proof[15],
        )
        return proof[0], key
