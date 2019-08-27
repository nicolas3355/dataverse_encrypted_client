# Used for encrypting the files to be uploaded to dataverse
from miscreant.aes.siv import SIV
import os
import argon2
import base64
import json
import nacl.utils
from nacl.public import PrivateKey, SealedBox

def enc_file(filepath):
    key = SIV.generate_key()
    siv = SIV(key)
    nonce = os.urandom(16)

    with open(filepath, 'r') as myfile:
        data = myfile.read().encode()
        ciphertext = siv.seal(data, [nonce])
        return (key, nonce, nonce + ciphertext)
        #returning ciphertext with the nonce (first 16 bytes)
    return None


def dec_file(filepath, data_key):
    siv = SIV(data_key)
    with open(filepath, 'rb') as myfile:
        ciphertext = myfile.read()
        # first 16 bytes are the nonce
        nonce = ciphertext[:16]
        plaintext = siv.open(ciphertext[16:], [nonce])
        return plaintext.decode()
    return None


def dec_str(ciphertext, data_key):
    siv = SIV(data_key)
    nonce = ciphertext[:16]
    plaintext = siv.open(ciphertext[16:], [nonce])
    return plaintext.decode()


def wrap_key_org(public_key_org, data_key):
    sealed_box = SealedBox(public_key_org)
    msg = data_key
    ciphertext = sealed_box.encrypt(msg)
    return ciphertext



def unwrap_key_org(secret_key, ciphertext):
	unseal_box = SealedBox(secret_key)
	plaintext = unseal_box.decrypt(ciphertext)
	return plaintext


def wrap_key_owner(passphrase, data_key):
    """
    data_key must be encoded

    Using argon2.low_level function, which is technically a hazmat
    function, but it doesn't appear to have any dangerous problems. We
    can't use the argon2.PasswordHasher() functions because they compress
    the hash and metadata using Blake2b and you can't extract the raw
    bytes of the hash or salt, which we need for the SIV.
    """

    #derive key using passphrase and salt
    salt = os.urandom(16)
    derived_key = argon2.low_level.hash_secret_raw(passphrase.encode(), 
        salt, time_cost=1, memory_cost=8, parallelism=1, hash_len=32,
        type=argon2.low_level.Type.I)

    # wrap the data key using the derived key
    siv = SIV(derived_key)
    ciphertext = siv.seal(data_key)

    # add salt to the start of ciphertext
    ciphertext = salt + ciphertext
    return ciphertext


def unwrap_key_owner(passphrase, wrapped_key_ciphertext):
	#derive key using passphrase and salt
	salt = wrapped_key_ciphertext[:16]
	derived_key = argon2.low_level.hash_secret_raw(passphrase.encode(), 
        salt, time_cost=1, memory_cost=8, parallelism=1, hash_len=32,
        type=argon2.low_level.Type.I)

	# unwrap the data key using the derived key
	siv = SIV(derived_key)
	data_key = siv.open(wrapped_key_ciphertext[16:])
	return data_key


def dec_file_owner(passphrase, metadata_file, encrypted_file):
    # need to have pulled the metadata.txt file and the
    # encrypted_test_file.txt file
    # get owner key from metadata and use to decrypt the file
    # this is if you want to first download and then read file
    file = open(metadata_file,'r')
    metadata = json.load(file)
    file.close()
    owner_key = metadata['files']['encrypted_test_file.txt']['owner_wrapped_key']


    k = base64.decodestring(owner_key.encode())
    key = unwrap_key_owner(passphrase, k)
    end = dec_file(encrypted_file,key)
    return end









