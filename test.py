from ciphers import Kyber512

def test_kyber512():
    kyber = Kyber512()
    public_key, secret_key = kyber.generate_keypair()
    ciphertext, shared_secret_enc = kyber.encapsulate(public_key)
    shared_secret_dec = kyber.decapsulate(secret_key, ciphertext)
    assert shared_secret_enc == shared_secret_dec, "Kyber512 - Shared secrets do not match!"

def test():
    test_kyber512()

if __name__ == "__main__":
    test()