from ciphers import Kyber512

def main():
    kyber = Kyber512()
    public_key, secret_key = kyber.generate_keypair()
    # print("Public Key:", public_key.hex())
    # print("Secret Key:", secret_key.hex())

    ciphertext, shared_secret_enc = kyber.encapsulate(public_key)
    print("Ciphertext:", ciphertext.hex())
    print("Shared Secret (Encapsulation):", shared_secret_enc.hex())

    shared_secret_dec = kyber.decapsulate(secret_key, ciphertext)
    print("Shared Secret (Decapsulation):", shared_secret_dec.hex())

    assert shared_secret_enc == shared_secret_dec, "Shared secrets do not match!"

if __name__ == "__main__":
    main()
