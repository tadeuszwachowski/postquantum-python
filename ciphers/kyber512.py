import ctypes
import os

# Path to liboqs shared library
current_dir = os.path.dirname(os.path.abspath(__file__))
liboqs_path = os.path.join(current_dir, '..', 'liboqs', 'build', 'lib', 'liboqs.so')  # Adjust path as needed
liboqs = ctypes.CDLL(liboqs_path)

# Constants for Kyber512
KYBER512_SECRET_KEY_LEN = 1632
KYBER512_PUBLIC_KEY_LEN = 800
KYBER512_CIPHERTEXT_LEN = 768
KYBER512_SHARED_SECRET_LEN = 32

# Function return type annotations
liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
liboqs.OQS_KEM_new.restype = ctypes.c_void_p

liboqs.OQS_KEM_free.argtypes = [ctypes.c_void_p]

liboqs.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_KEM_keypair.restype = ctypes.c_int

liboqs.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_KEM_encaps.restype = ctypes.c_int

liboqs.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_KEM_decaps.restype = ctypes.c_int


# Define the Kyber512 cipher class
class Kyber512:
    def __init__(self):
        self.kem = liboqs.OQS_KEM_new(b"Kyber512")
        if not self.kem:
            raise RuntimeError("Failed to initialize Kyber512")

    def generate_keypair(self):
        public_key = ctypes.create_string_buffer(KYBER512_PUBLIC_KEY_LEN)
        secret_key = ctypes.create_string_buffer(KYBER512_SECRET_KEY_LEN)
        result = liboqs.OQS_KEM_keypair(self.kem, public_key, secret_key)
        if result != 0:
            raise RuntimeError("Keypair generation failed")
        return public_key.raw, secret_key.raw

    def encapsulate(self, public_key):
        ciphertext = ctypes.create_string_buffer(KYBER512_CIPHERTEXT_LEN)
        shared_secret = ctypes.create_string_buffer(KYBER512_SHARED_SECRET_LEN)
        result = liboqs.OQS_KEM_encaps(self.kem, ciphertext, shared_secret, public_key)
        if result != 0:
            raise RuntimeError("Encapsulation failed")
        return ciphertext.raw, shared_secret.raw

    def decapsulate(self, secret_key, ciphertext):
        shared_secret = ctypes.create_string_buffer(KYBER512_SHARED_SECRET_LEN)
        result = liboqs.OQS_KEM_decaps(self.kem, shared_secret, ciphertext, secret_key)
        if result != 0:
            raise RuntimeError("Decapsulation failed")
        return shared_secret.raw

    def __del__(self):
        if self.kem:
            liboqs.OQS_KEM_free(self.kem)
