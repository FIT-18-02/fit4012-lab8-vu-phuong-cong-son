import hashlib
import os
import struct
from typing import Tuple

from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

DES_BLOCK_SIZE = 8
DES_KEY_SIZE = 8
DES_IV_SIZE = 8
LENGTH_HEADER_SIZE = 4
SHA256_DIGEST_SIZE = 32

def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def encrypt_des_cbc(plaintext: bytes, des_key: bytes = None, iv: bytes = None):
    if des_key is None or iv is None:
        des_key = os.urandom(DES_KEY_SIZE)
        iv = os.urandom(DES_IV_SIZE)
    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext, DES_BLOCK_SIZE))
    return des_key, iv, iv + encrypted

def decrypt_des_cbc(des_key: bytes, ciphertext_with_iv: bytes) -> bytes:
    iv = ciphertext_with_iv[:DES_IV_SIZE]
    ciphertext = ciphertext_with_iv[DES_IV_SIZE:]
    cipher = DES.new(des_key, DES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES_BLOCK_SIZE)

def encrypt_des_key_rsa(des_key: bytes, public_key) -> bytes:
    return PKCS1_OAEP.new(public_key).encrypt(des_key)

def decrypt_des_key_rsa(encrypted_key: bytes, private_key) -> bytes:
    return PKCS1_OAEP.new(private_key).decrypt(encrypted_key)

def build_secure_packet(encrypted_key: bytes, ciphertext: bytes, hash_val: bytes) -> bytes:
    return struct.pack('!I', len(encrypted_key)) + encrypted_key + struct.pack('!I', len(ciphertext)) + ciphertext + hash_val

def parse_secure_packet(packet: bytes):
    offset = 0
    key_len = struct.unpack('!I', packet[offset:offset+4])[0]
    offset += 4
    encrypted_key = packet[offset:offset+key_len]
    offset += key_len
    cipher_len = struct.unpack('!I', packet[offset:offset+4])[0]
    offset += 4
    ciphertext = packet[offset:offset+cipher_len]
    offset += cipher_len
    hash_val = packet[offset:offset+32]
    return encrypted_key, ciphertext, hash_val

def recv_secure_packet(conn):
    key_len = struct.unpack('!I', conn.recv(4))[0]
    encrypted_key = conn.recv(key_len)
    cipher_len = struct.unpack('!I', conn.recv(4))[0]
    ciphertext = conn.recv(cipher_len)
    hash_val = conn.recv(32)
    return encrypted_key, ciphertext, hash_val

def build_sender_payload(plaintext: bytes, public_key):
    hash_val = sha256_digest(plaintext)
    des_key, _, ciphertext = encrypt_des_cbc(plaintext)
    encrypted_key = encrypt_des_key_rsa(des_key, public_key)
    return build_secure_packet(encrypted_key, ciphertext, hash_val), des_key, ciphertext, hash_val

def open_receiver_payload(packet: bytes, private_key):
    encrypted_key, ciphertext, received_hash = parse_secure_packet(packet)
    des_key = decrypt_des_key_rsa(encrypted_key, private_key)
    plaintext = decrypt_des_cbc(des_key, ciphertext)
    return plaintext, sha256_digest(plaintext) == received_hash
