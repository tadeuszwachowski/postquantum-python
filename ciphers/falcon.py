import ctypes

from .helper import liboqs

class Falcon:
    def __init__(self, algorithm_name, public_key_len, secret_key_len, signature_len):
        self.algorithm_name = algorithm_name.encode()
        self.public_key_len = public_key_len
        self.secret_key_len = secret_key_len
        self.signature_len = signature_len

        # Initialize the signature object
        self.sig = liboqs.OQS_SIG_new(self.algorithm_name)
        if not self.sig:
            raise RuntimeError(f"Failed to initialize {algorithm_name}")

    def generate_keypair(self):
        # Allocate buffers for keys      
        public_key = ctypes.create_string_buffer(self.public_key_len)
        secret_key = ctypes.create_string_buffer(self.secret_key_len)
        
        result = liboqs.OQS_SIG_keypair(self.sig, public_key, secret_key)
        
        if result != 0:
            raise RuntimeError(f"Keypair generation failed for {self.algorithm_name.decode()}")
        return public_key.raw, secret_key.raw

    def sign(self, message, secret_key):
        # Allocate buffer for the signature
        signature = ctypes.create_string_buffer(self.signature_len)
        signature_len = ctypes.c_size_t(0)

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

        # Truncate the signature to the actual length
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


# Define specific Falcon variants
class Falcon512(Falcon):
    def __init__(self):
        super().__init__("Falcon-512", 897, 1281, 666)

class Falcon1024(Falcon):
    def __init__(self):
        super().__init__("Falcon-1024", 1793, 2305, 1280)
