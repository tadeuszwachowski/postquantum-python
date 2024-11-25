from ciphers import KEMCipher, Kyber512, Kyber768, Kyber1024
from ciphers import Dilithium, Dilithium2, Dilithium3, Dilithium5
from ciphers import Falcon, Falcon512, Falcon1024

def testf(func):
    def wrapper(*args, **kwargs):
        try:
            result = func(*args, **kwargs)
            print(f"[+] {func.__name__} - ok")
            return result
        except AssertionError:
            raise  # Re-raise the AssertionError
    return wrapper


# Encapsulation
@testf
def test_kem():
    kyber512 = KEMCipher("Kyber512", 800, 1632, 768, 32)
    public_key, secret_key = kyber512.generate_keypair()
    ciphertext, shared_secret_enc = kyber512.encapsulate(public_key)
    shared_secret_dec = kyber512.decapsulate(secret_key, ciphertext)
    assert shared_secret_enc == shared_secret_dec, "KEM - Shared secrets do not match!"

@testf
def test_kyber512():
    kyber = Kyber512()
    public_key, secret_key = kyber.generate_keypair()
    ciphertext, shared_secret_enc = kyber.encapsulate(public_key)
    shared_secret_dec = kyber.decapsulate(secret_key, ciphertext)
    assert shared_secret_enc == shared_secret_dec, "Kyber512 - Shared secrets do not match!"

@testf
def test_kyber768():
    kyber = Kyber768()
    public_key, secret_key = kyber.generate_keypair()
    ciphertext, shared_secret_enc = kyber.encapsulate(public_key)
    shared_secret_dec = kyber.decapsulate(secret_key, ciphertext)
    assert shared_secret_enc == shared_secret_dec, "Kyber768 - Shared secrets do not match!"

@testf
def test_kyber1024():
    kyber = Kyber1024()
    public_key, secret_key = kyber.generate_keypair()
    ciphertext, shared_secret_enc = kyber.encapsulate(public_key)
    shared_secret_dec = kyber.decapsulate(secret_key, ciphertext)
    assert shared_secret_enc == shared_secret_dec, "Kyber768 - Shared secrets do not match!"



# Signature - Dilithium
@testf
def test_dilithium():
    dilithium = Dilithium("Dilithium2", 1312, 2528, 2420)
    public_key, secret_key = dilithium.generate_keypair()
    message = b"Hello, post-quantum world!"
    signature = dilithium.sign(message, secret_key)
    try:
        verification = dilithium.verify(message, signature, public_key)
    except RuntimeError as e:
        print("Dilithium2 - Verification failed:", e)
    assert verification, 'Error when veryfying'

@testf
def test_dilithium2():
    dilithium = Dilithium2()
    public_key, secret_key = dilithium.generate_keypair()
    message = b"Hello, post-quantum world!"
    signature = dilithium.sign(message, secret_key)
    try:
        verification = dilithium.verify(message, signature, public_key)
    except RuntimeError as e:
        print("Dilithium2 - Verification failed:", e)
    assert verification, 'Error when veryfying'

@testf
def test_dilithium3():
    dilithium = Dilithium3()
    public_key, secret_key = dilithium.generate_keypair()
    message = b"Hello, post-quantum world!"
    signature = dilithium.sign(message, secret_key)
    try:
        verification = dilithium.verify(message, signature, public_key)
    except RuntimeError as e:
        print("Dilithium3 - Verification failed:", e)
    assert verification, 'Error when veryfying'

@testf
def test_dilithium5():
    dilithium = Dilithium5()
    public_key, secret_key = dilithium.generate_keypair()
    message = b"Hello, post-quantum world!"
    signature = dilithium.sign(message, secret_key)
    try:
        verification = dilithium.verify(message, signature, public_key)
    except RuntimeError as e:
        print("Dilithium5 - Verification failed:", e)
    assert verification, 'Error when veryfying'



# Signature - Falcon
@testf
def test_falcon():
    falcon = Falcon("Falcon-512", 897, 1281, 690)
    public_key, secret_key = falcon.generate_keypair()
    message = b"Hello, post-quantum world!"
    signature = falcon.sign(message, secret_key)
    try:
        is_verified = falcon.verify(message, signature, public_key)
    except RuntimeError as e:
        print("Falcon:", e)
    assert is_verified, 'Error when veryfying'

@testf
def test_falcon512():
    falcon = Falcon512()
    public_key, secret_key = falcon.generate_keypair()
    message = b"Hello, post-quantum world!"
    signature = falcon.sign(message, secret_key)
    try:
        is_verified = falcon.verify(message, signature, public_key)
    except RuntimeError as e:
        print("Falcon512:", e)
    assert is_verified, 'Error when veryfying'

@testf
def test_falcon1024():
    falcon = Falcon1024()
    public_key, secret_key = falcon.generate_keypair()
    message = b"Hello, post-quantum world!"
    signature = falcon.sign(message, secret_key)
    try:
        is_verified = falcon.verify(message, signature, public_key)
    except RuntimeError as e:
        print("Falcon1024:", e)
    assert is_verified, 'Error when veryfying'


# Test
def test():
    # encapsulation
    test_kem()
    test_kyber512()
    test_kyber768()
    test_kyber1024()

    # signing
    test_dilithium()
    test_dilithium2()
    test_dilithium3()
    test_dilithium5()

    # Falcon
    test_falcon()
    test_falcon512()
    test_falcon1024()
    print("OK.")

if __name__ == "__main__":
    test()