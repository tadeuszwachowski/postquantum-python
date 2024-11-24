import ctypes

from .helper import liboqs

class KEMCipher:
    def __init__(self, algorithm_name, public_key_len, secret_key_len, ciphertext_len, shared_secret_len):
        self.algorithm_name = algorithm_name.encode()
        self.public_key_len = public_key_len
        self.secret_key_len = secret_key_len
        self.ciphertext_len = ciphertext_len
        self.shared_secret_len = shared_secret_len

        self.kem = liboqs.OQS_KEM_new(self.algorithm_name)
        if not self.kem:
            raise RuntimeError(f"Failed to initialize {algorithm_name}")

    def generate_keypair(self):
        public_key = ctypes.create_string_buffer(self.public_key_len)
        secret_key = ctypes.create_string_buffer(self.secret_key_len)
        result = liboqs.OQS_KEM_keypair(self.kem, public_key, secret_key)
        if result != 0:
            raise RuntimeError(f"Keypair generation failed for {self.algorithm_name.decode()}")
        return public_key.raw, secret_key.raw

    def encapsulate(self, public_key):
        ciphertext = ctypes.create_string_buffer(self.ciphertext_len)
        shared_secret = ctypes.create_string_buffer(self.shared_secret_len)
        result = liboqs.OQS_KEM_encaps(self.kem, ciphertext, shared_secret, public_key)
        if result != 0:
            raise RuntimeError(f"Encapsulation failed for {self.algorithm_name.decode()}")
        return ciphertext.raw, shared_secret.raw

    def decapsulate(self, secret_key, ciphertext):
        shared_secret = ctypes.create_string_buffer(self.shared_secret_len)
        result = liboqs.OQS_KEM_decaps(self.kem, shared_secret, ciphertext, secret_key)
        if result != 0:
            raise RuntimeError(f"Decapsulation failed for {self.algorithm_name.decode()}")
        return shared_secret.raw

    def __del__(self):
        if self.kem:
            liboqs.OQS_KEM_free(self.kem)

# Define specific Kyber variants
class Kyber512(KEMCipher):
    def __init__(self):
        super().__init__("Kyber512", 800, 1632, 768, 32)

class Kyber768(KEMCipher):
    def __init__(self):
        super().__init__("Kyber768", 1184, 2400, 1088, 32)

class Kyber1024(KEMCipher):
    def __init__(self):
        super().__init__("Kyber1024", 1568, 3168, 1568, 32)