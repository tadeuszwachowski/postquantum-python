import ctypes
import os

# Path to liboqs shared library
current_dir = os.path.dirname(os.path.abspath(__file__))
liboqs_path = os.path.join(current_dir, '..', 'liboqs', 'build', 'lib', 'liboqs.so')  # Adjust path as needed
liboqs = ctypes.CDLL(liboqs_path)

# General
liboqs.OQS_KEM_new.argtypes = [
    ctypes.c_char_p  # Algorithm name
]
liboqs.OQS_KEM_new.restype = ctypes.c_void_p

liboqs.OQS_KEM_free.argtypes = [
    ctypes.c_void_p  # KEM object to be freed
]

liboqs.OQS_KEM_keypair.argtypes = [
    ctypes.c_void_p,  # KEM object
    ctypes.c_char_p,  # Public key buffer
    ctypes.c_char_p   # Private key buffer
]
liboqs.OQS_KEM_keypair.restype = ctypes.c_int  # Return value

liboqs.OQS_KEM_encaps.argtypes = [
    ctypes.c_void_p,  # KEM object
    ctypes.c_char_p,  # Ciphertext buffer
    ctypes.c_char_p,  # Shared secret buffer
    ctypes.c_char_p   # Public key (encapsulation)
]
liboqs.OQS_KEM_encaps.restype = ctypes.c_int  # Return value

liboqs.OQS_KEM_decaps.argtypes = [
    ctypes.c_void_p,  # KEM object
    ctypes.c_char_p,  # Shared secret buffer
    ctypes.c_char_p,  # Ciphertext buffer
    ctypes.c_char_p   # Public key (decapsulation)
]
liboqs.OQS_KEM_decaps.restype = ctypes.c_int  # Return value

# CRYSTALS-Dilithium
liboqs.OQS_SIG_new.argtypes = [
    ctypes.c_char_p  # Algorithm name
]
liboqs.OQS_SIG_new.restype = ctypes.c_void_p  # Pointer to the SIG object

liboqs.OQS_SIG_free.argtypes = [
    ctypes.c_void_p  # SIG object to be freed
]

liboqs.OQS_SIG_keypair.argtypes = [
    ctypes.c_void_p,  # SIG object
    ctypes.c_char_p,  # Public key buffer
    ctypes.c_char_p   # Private key buffer
]
liboqs.OQS_SIG_keypair.restype = ctypes.c_int  # Return value

liboqs.OQS_SIG_alg_identifier.argtypes = [
    ctypes.c_size_t  # Algorithm index
]
liboqs.OQS_SIG_alg_identifier.restype = ctypes.c_char_p  # Returns a null-terminated string with the algorithm identifier

liboqs.OQS_SIG_alg_count.restype = ctypes.c_size_t  # Returns the count of supported algorithms

liboqs.OQS_SIG_sign.argtypes = [
    ctypes.c_void_p,             # SIG object
    ctypes.c_char_p,             # Buffer to store the signature
    ctypes.POINTER(ctypes.c_size_t),  # Pointer to store the signature length
    ctypes.c_char_p,             # Message to be signed
    ctypes.c_size_t,             # Length of the message
    ctypes.c_char_p              # Private key used for signing
]
liboqs.OQS_SIG_sign.restype = ctypes.c_int  # Returns 0 on success, non-zero on failure

liboqs.OQS_SIG_verify.argtypes = [
    ctypes.c_void_p,             # SIG object
    ctypes.c_char_p,             # Message to verify
    ctypes.c_size_t,             # Length of the message
    ctypes.c_char_p,             # Signature to verify
    ctypes.c_size_t,             # Length of the signature
    ctypes.c_char_p              # Public key used for verification
]
liboqs.OQS_SIG_verify.restype = ctypes.c_int  # Returns 0 on success, non-zero on failure

