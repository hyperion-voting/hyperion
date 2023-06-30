import pytest
import sys

import threshold_crypto as tc
import gmpy2


sys.path.append(".")
from curve import Curve
from primitives import ElGamalEncryption, NIZK, DSA, ChaumPedersenProof
#from group import DHGroup
from subroutines import Mixnet

from parties import Teller
#key_params = tc.static_2048_key_parameters()


@pytest.fixture
def generate_curve():
    return Curve('P-256')

def test_curve_random(generate_curve):
    random = generate_curve.get_random()
    assert isinstance(random, int)

def test_dhgroup_n_random(generate_curve):
    count = 5
    randoms = generate_curve.get_random_n(count)
    for random in randoms:
        assert isinstance(random, int)
    assert len(randoms) == count


def test_elgamal_enc(generate_curve):
    curve = generate_curve
    ege = ElGamalEncryption(curve)
    secret_key, public_key = ege.keygen()
    message = 5 * curve.get_pars().P
    ciphertext = ege.encrypt(public_key, message)
    assert (message ) == ege.decrypt(secret_key, ciphertext)
    ciphertext_2 = ege.re_encrypt(public_key, ciphertext)
    assert (message ) == ege.decrypt(secret_key, ciphertext_2)


def test_nizk(generate_curve):
    nizk = NIZK(generate_curve)
    secret_key = generate_curve.get_random()
    public_key = secret_key * generate_curve.get_pars().P
    proof = nizk.prove(secret_key, public_key, "id")
    assert nizk.verify(proof, public_key, "id")


def test_chaum_pedersen_proof_or_n(generate_curve):
    chmp = ChaumPedersenProof(generate_curve)
    secret_key = generate_curve.get_random()
    r = generate_curve.get_random()
    label = "id"
    public_key = secret_key * generate_curve.get_pars().P
    message_0 = 0 * generate_curve.get_pars().P
    message_1 = 1 * generate_curve.get_pars().P
    message_5 = 5 * generate_curve.get_pars().P
    ciphertext1 = r * generate_curve.get_pars().P
    ciphertext_2_0 = message_0 + (public_key * r)
    ciphertext_2_1 = message_1 + (public_key * r)
    ciphertext_2_5 = message_5 + (public_key * r)
    ciphertext_0 = {"c1": ciphertext1, "c2": ciphertext_2_0}
    ciphertext_1 = {"c1": ciphertext1, "c2": ciphertext_2_1}
    ciphertext_5 = {"c1": ciphertext1, "c2": ciphertext_2_5}
    proof_0 = chmp.prove_or_n(ciphertext_0, r, public_key, 4, 0, label)
    proof_1 = chmp.prove_or_n(ciphertext_1, r, public_key, 4, 1, label)
    proof_5 = chmp.prove_or_n(ciphertext_5, r, public_key, 4, 2, label)
    assert (
        chmp.verify_or_n(
            ciphertext_0,
            public_key,
            proof_0[0],
            proof_0[1],
            proof_0[2],
            proof_0[3],
            label,
        )
        == 1
    )
    assert (
        chmp.verify_or_n(
            ciphertext_1,
            public_key,
            proof_1[0],
            proof_1[1],
            proof_1[2],
            proof_1[3],
            label,
        )
        == 1
    )
    assert (
        chmp.verify_or_n(
            ciphertext_5,
            public_key,
            proof_5[0],
            proof_5[1],
            proof_5[2],
            proof_5[3],
            label,
        )
        == 0
    )


def test_chaum_pedersen_proof(generate_curve):
    chmp = ChaumPedersenProof(generate_curve)
    secret_key = generate_curve.get_random()
    r = generate_curve.get_random()
    public_key = secret_key * generate_curve.get_pars().P
    message = 0 * generate_curve.get_pars().P
    ciphertext_1 = r * generate_curve.get_pars().P 
    ciphertext_2 = (message) + (public_key * r)
    ciphertext = {"c1": ciphertext_1, "c2": ciphertext_2}
    proof = chmp.prove(ciphertext, r, public_key)
    assert chmp.verify(ciphertext, public_key, proof[0], proof[1])


def test_chaum_pedersen_proof_or(generate_curve):
    chmp = ChaumPedersenProof(generate_curve)
    secret_key = generate_curve.get_random()
    r = generate_curve.get_random()
    public_key = secret_key * generate_curve.get_pars().P
    message = 0 * generate_curve.get_pars().P
    ciphertext_1 = r * generate_curve.get_pars().P 
    ciphertext_2 = (message) + (public_key * r)
    ciphertext = {"c1": ciphertext_1, "c2": ciphertext_2}
    proof = chmp.prove_or_n(ciphertext, r, public_key,5,0,"test")
    assert chmp.verify_or_n(ciphertext, public_key, proof[0], proof[1], proof[2], proof[3],"test")

def test_dsa(generate_curve):
    dsa = DSA(generate_curve)
    signing_key, verification_key = dsa.keygen()
    message = 15
    signature = dsa.sign(signing_key, message)
    assert dsa.verify(verification_key, signature, message)


def test_proof_2(generate_curve):
    ege = ElGamalEncryption(generate_curve)
    teller_secret_key, teller_public_key = ege.keygen()
    voter_secret_key, voter_public_key = ege.keygen()
    r_i = generate_curve.get_random()
    message = r_i * voter_public_key
    ciphertext = ege.encrypt(teller_public_key, message)
    nizk = NIZK(generate_curve)
    proof = nizk.proof_2(
        ciphertext, teller_public_key, voter_public_key, ciphertext[2], r_i
    )
    assert (
        nizk.verify_2(ciphertext, teller_public_key, voter_public_key, proof)
        == 1
    )
    ciphertext_f = ege.encrypt(teller_public_key, generate_curve.get_pars().P)
    proof = nizk.proof_2(
        ciphertext_f, teller_public_key, voter_public_key, ciphertext_f[2], r_i
    )
    assert (
        nizk.verify_2(ciphertext_f, teller_public_key, voter_public_key, proof)
        == 0
    )

def test_tp_decrypt(generate_curve):
    curve_params = tc.CurveParameters('P-256')
    thresh_params = tc.ThresholdParameters(3, 5)
    pub_key, key_shares = tc.central.create_public_key_and_shares_centralized(curve_params, thresh_params)
    message = 'Some secret message to be encrypted!'
    encrypted_message = tc.central.encrypt_message(message, pub_key)
    reconstruct_shares = [key_shares[i] for i in [0, 2, 4]]  # choose 3 of 5 key shares
    partial_decryptions = [tc.participant.compute_partial_decryption(encrypted_message, share) for share in reconstruct_shares]
    decrypted_message = tc.central.decrypt_message(partial_decryptions, encrypted_message, thresh_params)
    assert(message == decrypted_message)

def test_threshold_decrypt(generate_curve):
    ege = ElGamalEncryption(generate_curve)
    teller_public_key, teller_sk = Teller.generate_threshold_keys(
        2, 3, generate_curve.get_pars()
    )
    message = 5 * generate_curve.get_pars().P
    ciphertext = ege.encrypt(teller_public_key.Q,message)
    pd = []
    teller = Teller(generate_curve,teller_sk[0],teller_public_key)
    for i in range(len(teller_sk)):
        temp_pd = ege.partial_decrypt(ciphertext,teller_sk[i])
        pd.append(teller.serialize_pd(temp_pd))
    ciphertext = tc.EncryptedMessage(ciphertext[0], ciphertext[1], "")
    decr = ege.threshold_decrypt(pd,ciphertext, tc.ThresholdParameters(2, 3))
    assert(decr == message)

