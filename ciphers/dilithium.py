import ctypes

from .helper import liboqs

# Define shared class for CRYSTALS-Dilithium variants
class Dilithium:
    def __init__(self, algorithm_name, public_key_len, secret_key_len, signature_len):
        self.algorithm_name = algorithm_name.encode()
        self.public_key_len = public_key_len
        self.secret_key_len = secret_key_len
        self.signature_len = signature_len

        self.sig = liboqs.OQS_SIG_new(self.algorithm_name)
        if not self.sig:
            raise RuntimeError(f"Failed to initialize {algorithm_name}")

    def generate_keypair(self):
        public_key = ctypes.create_string_buffer(self.public_key_len)
        secret_key = ctypes.create_string_buffer(self.secret_key_len)

        if not self.sig:
            raise RuntimeError("SIG object is not initialized correctly")

        result = liboqs.OQS_SIG_keypair(self.sig, public_key, secret_key)

        if result != 0:
            raise RuntimeError("Keypair generation failed")
        return public_key.raw, secret_key.raw


    def sign(self, message, secret_key):
        signature = ctypes.create_string_buffer(self.signature_len)  # Allocate memory
        signature_len = ctypes.c_size_t(self.signature_len)  # Length container
        result = liboqs.OQS_SIG_sign(
            self.sig,
            signature,
            ctypes.byref(signature_len),
            message,
            len(message),
            secret_key,
        )
        if result != 0:
            raise RuntimeError(f"Signing failed for {self.algorithm_name.decode()}")
        return signature.raw[:signature_len.value]


    def verify(self, message, signature, public_key):
        result = liboqs.OQS_SIG_verify(
            self.sig,
            message,
            len(message),
            signature,
            len(signature),
            public_key,
        )
        if result != 0:
            raise RuntimeError(f"Verification failed for {self.algorithm_name.decode()}")
        return True


    def __del__(self):
        if self.sig:
            liboqs.OQS_SIG_free(self.sig)

# Define specific Dilithium variants
class Dilithium2(Dilithium):
    def __init__(self):
        super().__init__("Dilithium2", 1312, 2528, 2420)

class Dilithium3(Dilithium):
    def __init__(self):
        super().__init__("Dilithium3", 1952, 4000, 3293)

class Dilithium5(Dilithium):
    def __init__(self):
        super().__init__("Dilithium5", 2592, 4864, 4595)
