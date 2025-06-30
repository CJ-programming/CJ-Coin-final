from base64 import b64encode

from Crypto.Cipher.AES import new, MODE_CBC, block_size
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad

from getpass import getpass

from hashlib import sha256

from math import ceil

from os.path import exists
from os.path import getsize

def prefix_length(data : bytes) -> bytes:
    len_data = len(data).to_bytes(1, 'little') + data
    return len_data

def get_prefix_data(data : bytes) -> list:
    values = []
    offset = 0

    while offset < len(data):
        length = data[offset]
        offset += 1
        value = data[offset:offset+length]
        offset += length
        values.append(value)

    return values

def create_password():
    if exists('key.bin') and getsize('key.bin') > 0:
        return

    with open('key.bin', 'wb') as f:
        password = getpass('Create password: ').encode('utf-8')

        salt = get_random_bytes(32)
        salt_pbkdf2 = get_random_bytes(32)

        pepper = get_random_bytes(1)

        salt_pepper_password = password + salt + pepper

        key = PBKDF2(salt_pepper_password, salt_pbkdf2)

        password_hash = sha256(sha256(key).digest()).digest()

        f.write(prefix_length(password_hash))
        f.write(prefix_length(salt))
        f.write(prefix_length(salt_pbkdf2))

        return password

def decrypt_file(file, key):
    with open(file, 'rb') as f:
        iv = f.read(16)
        data = f.read()

    cipher = new(key, MODE_CBC, iv)
    decrypt_data = unpad(cipher.decrypt(data), block_size)

    return decrypt_data

def str_encode_b64(data_bytes : bytes) -> str:
    b64_str = b64encode(data_bytes).decode('utf-8')
    return b64_str

def gen_check_sum(data : bytes) -> bytes:
    checksum = sha256(sha256(data).digest()).hexdigest()

    data_checksum_json = {'checksum' : checksum, 'data' : data}

    return data_checksum_json

def integer_to_bytes(integer : int) -> bytes:
    integer_bit_length = integer.bit_length()

    if not integer_bit_length:
        integer_bit_length = 1

    data_bytes = integer.to_bytes(ceil(integer_bit_length / 8), 'big')

    return data_bytes

def verify_password(password):
    with open('key.bin', 'rb') as f:
        file_data = f.read()
        key_hash, salt, salt_pbkdf2 = get_prefix_data(file_data)

    salt_password = password + salt

    for pepper in range(2**8 - 1):
        pepper_bytes = pepper.to_bytes(1, byteorder='big')
        full_password = salt_password + pepper_bytes

        key = PBKDF2(full_password, salt_pbkdf2)

        hash_guess = sha256(sha256(key).digest()).digest()

        if hash_guess == key_hash:
            return key
