import ctypes
import os

# Path to liboqs shared library
current_dir = os.path.dirname(os.path.abspath(__file__))
liboqs_path = os.path.join(current_dir, '..', 'liboqs', 'build', 'lib', 'liboqs.so')  # Adjust path as needed
liboqs = ctypes.CDLL(liboqs_path)

# General
liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
liboqs.OQS_KEM_new.restype = ctypes.c_void_p

liboqs.OQS_KEM_free.argtypes = [ctypes.c_void_p]

liboqs.OQS_KEM_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_KEM_keypair.restype = ctypes.c_int

liboqs.OQS_KEM_encaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_KEM_encaps.restype = ctypes.c_int

liboqs.OQS_KEM_decaps.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_KEM_decaps.restype = ctypes.c_int

# CRYSTALS-Dilithium
liboqs.OQS_SIG_new.argtypes = [ctypes.c_char_p]
liboqs.OQS_SIG_new.restype = ctypes.c_void_p

liboqs.OQS_SIG_free.argtypes = [ctypes.c_void_p]

liboqs.OQS_SIG_keypair.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
liboqs.OQS_SIG_keypair.restype = ctypes.c_int

liboqs.OQS_SIG_alg_identifier.argtypes = [ctypes.c_size_t]
liboqs.OQS_SIG_alg_identifier.restype = ctypes.c_char_p

liboqs.OQS_SIG_alg_count.restype = ctypes.c_size_t

liboqs.OQS_SIG_sign.argtypes = [
    ctypes.c_void_p,  # sig object
    ctypes.c_char_p,  # signature
    ctypes.POINTER(ctypes.c_size_t),  # signature_len
    ctypes.c_char_p,  # message
    ctypes.c_size_t,  # message_len
    ctypes.c_char_p,  # secret_key
]
liboqs.OQS_SIG_sign.restype = ctypes.c_int

liboqs.OQS_SIG_verify.argtypes = [
    ctypes.c_void_p,  # sig object
    ctypes.c_char_p,  # message
    ctypes.c_size_t,  # message_len
    ctypes.c_char_p,  # signature
    ctypes.c_size_t,  # signature_len
    ctypes.c_char_p,  # public_key
]
liboqs.OQS_SIG_verify.restype = ctypes.c_int
