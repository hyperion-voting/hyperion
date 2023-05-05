import pytest
import sys

import threshold_crypto as tc
import gmpy2

sys.path.append(".")
from primitives import ChaumPedersenProof, ElGamalEncryption, NIZK, DSA
from group import DHGroup
from subroutines import Mixnet

key_params = tc.static_2048_key_parameters()


@pytest.fixture
def generate_group():
    return DHGroup(key_params.p, key_params.g, key_params.q)


def test_dhgroup(generate_group):
    pars = generate_group.get_pars()
    assert gmpy2.mpz(pars["p"]) == (gmpy2.mul(gmpy2.mpz(pars["q"]), 2) + 1)
    assert generate_group.raise_g(2) == gmpy2.powmod(pars["g"], 2, pars["p"])


def test_dhgroup_random(generate_group):
    pars = generate_group.get_pars()
    random = generate_group.get_random()
    assert isinstance(random, gmpy2.mpz) and random < gmpy2.mpz(pars["q"])


def test_dhgroup_n_random(generate_group):
    pars = generate_group.get_pars()
    count = 5
    randoms = generate_group.get_random_n(count)
    for random in randoms:
        assert isinstance(random, gmpy2.mpz)
        assert random < gmpy2.mpz(pars["q"])

    assert len(randoms) == count


def test_elgamal_enc(generate_group):
    pars = generate_group.get_pars()
    ege = ElGamalEncryption(generate_group)
    secret_key, public_key = ege.keygen()
    message = gmpy2.powmod(pars["g"], 2, pars["p"])
    ciphertext = ege.encrypt(public_key, message)
    assert message == ege.decrypt(secret_key, ciphertext)
    ciphertext_2 = ege.re_encrypt(public_key, ciphertext)
    assert message == ege.decrypt(secret_key, ciphertext_2)


def test_nizk(generate_group):
    pars = generate_group.get_pars()
    nizk = NIZK(generate_group)
    secret_key = generate_group.get_random()
    public_key = gmpy2.powmod(pars["g"], secret_key, pars["p"])
    proof = nizk.prove(secret_key, public_key, "id")
    assert nizk.verify(proof, public_key, "id")


def test_chaum_pedersen_proof_or_n(generate_group):
    pars = generate_group.get_pars()
    chmp = ChaumPedersenProof(generate_group)
    secret_key = generate_group.get_random()
    r = generate_group.get_random()
    label = "id"
    public_key = gmpy2.powmod(pars["g"], secret_key, pars["p"])
    message_0 = gmpy2.powmod(pars["g"], 0, pars["p"])
    message_1 = gmpy2.powmod(pars["g"], 1, pars["p"])
    message_5 = gmpy2.powmod(pars["g"], 5, pars["p"])
    ciphertext1 = gmpy2.powmod(pars["g"], r, pars["p"])
    ciphertext_2_0 = gmpy2.f_mod(
        gmpy2.mul(message_0, gmpy2.powmod(public_key, r, pars["p"])), pars["p"]
    )
    ciphertext_2_1 = gmpy2.f_mod(
        gmpy2.mul(message_1, gmpy2.powmod(public_key, r, pars["p"])), pars["p"]
    )
    ciphertext_2_5 = gmpy2.f_mod(
        gmpy2.mul(message_5, gmpy2.powmod(public_key, r, pars["p"])), pars["p"]
    )
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


def test_chaum_pedersen_proof(generate_group):
    pars = generate_group.get_pars()
    chmp = ChaumPedersenProof(generate_group)
    secret_key = generate_group.get_random()
    r = generate_group.get_random()
    public_key = gmpy2.powmod(pars["g"], secret_key, pars["p"])
    message = gmpy2.powmod(pars["g"], 0, pars["p"])
    ciphertext_1 = gmpy2.powmod(pars["g"], r, pars["p"])
    ciphertext_2 = gmpy2.f_mod(
        gmpy2.mul(message, gmpy2.powmod(public_key, r, pars["p"])), pars["p"]
    )
    ciphertext = {"c1": ciphertext_1, "c2": ciphertext_2}
    proof = chmp.prove(ciphertext, r, public_key)
    assert chmp.verify(ciphertext, public_key, proof[0], proof[1])


def test_chaum_pedersen_proof_or(generate_group):
    pars = generate_group.get_pars()
    chmp = ChaumPedersenProof(generate_group)
    secret_key = generate_group.get_random()
    r = generate_group.get_random()
    public_key = gmpy2.powmod(pars["g"], secret_key, pars["p"])
    message = gmpy2.powmod(pars["g"], 0, pars["p"])
    ciphertext_1 = gmpy2.powmod(pars["g"], r, pars["p"])
    ciphertext_2 = gmpy2.f_mod(
        gmpy2.mul(message, gmpy2.powmod(public_key, r, pars["p"])), pars["p"]
    )
    ciphertext = {"c1": ciphertext_1, "c2": ciphertext_2}
    proof = chmp.prove(ciphertext, r, public_key)
    assert chmp.verify(ciphertext, public_key, proof[0], proof[1])


def test_dsa(generate_group):
    pars = generate_group.get_pars()
    dsa = DSA(generate_group)
    signing_key, verification_key = dsa.keygen()
    message = gmpy2.powmod(pars["g"], 5, pars["p"])
    signature = dsa.sign(signing_key, message)
    assert dsa.verify(verification_key, signature, message)


def test_proof_2(generate_group):
    pars = generate_group.get_pars()
    ege = ElGamalEncryption(generate_group)
    teller_secret_key, teller_public_key = ege.keygen()
    voter_secret_key, voter_public_key = ege.keygen()
    r_i = generate_group.get_random()
    message = gmpy2.powmod(voter_public_key, r_i, pars["p"])
    ciphertext = ege.encrypt(teller_public_key, message)
    nizk = NIZK(generate_group)
    proof = nizk.proof_2(
        ciphertext, teller_public_key, voter_public_key, ciphertext[2], r_i
    )
    assert (
        nizk.verify_2(ciphertext, teller_public_key, voter_public_key, proof)
        == 1
    )
    ciphertext_f = ege.encrypt(teller_public_key, pars["g"])
    proof = nizk.proof_2(
        ciphertext_f, teller_public_key, voter_public_key, ciphertext_f[2], r_i
    )
    assert (
        nizk.verify_2(ciphertext_f, teller_public_key, voter_public_key, proof)
        == 0
    )

def test_exponentiation_mix(generate_group):
    pars = generate_group.get_pars()
    list = []
    for i in range(10):
        temp = []
        temp.append(0)
        temp.append(generate_group.raise_g(i))
        list.append(temp)
    
    key = generate_group.get_random()
    mx = Mixnet(generate_group)
    proof = mx.exponentiation_mix(list,key)
    print(mx.verify_exponentiation_mix(list,proof[0],proof[1],proof[2],proof[3],proof[4],proof[5],proof[6],proof[7],proof[8],proof[9],proof[10],proof[11],proof[12],proof[13],proof[14],proof[15]))
    