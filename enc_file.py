# Used for encrypting the files to be uploaded to dataverse
from miscreant.aes.siv import SIV
import os
import hashlib


def enc_file(filepath):
    key = SIV.generate_key()
    siv = SIV(key)
    nonce = os.urandom(16)

    with open(filepath, 'r') as myfile:
        data = myfile.read()
        ciphertext = siv.seal(data, [nonce])
        return (key, nonce, nonce + ciphertext)
    return None


def dec_file(filepath, data_key):
    siv = SIV(data_key)
    with open(filepath, 'rb') as myfile:
        ciphertext = myfile.read()
        # first 16 bytes are the nonce
        nonce = ciphertext[:16]
        plaintext = siv.open(ciphertext[16:], [nonce])
        return plaintext
    return None


def wrap_key_org(public_key_org, data_key):
    # wrap data key under public key?
    # miscreant is for symmetric encryption
    pass


def wrap_key_owner(passphrase, data_key):
    iterations = 10000
    dklen = 32
    salt = os.urandom(16)
    # owner_key = hmac(passphrase, so
    # hashlib.pbkdf2_hmac: (hash_name, password, salt, iterations, dklen=None)
    derived_key = hashlib.pbkdf2_hmac("sha512", passphrase, salt, iterations,
                                      dklen)

    # argon2 implementation
    # h = argon2.PasswordHasher()
    # https://argon2-cffi.readthedocs.io/en/stable/argon2.html
    # better use argon2i for our use case
    # u'$argon2id$v=19$m=102400,t=2,p=8$fUQzqlLHaEi+iTknR8cfpA$4Qf2rZ/SfBrTvzdEkDJUsQ'

    # ciphertext = encrypt(data_key, owner_key)
    siv = SIV(derived_key)
    ciphertext = siv.seal(data_key)

    # append the salt that was used to generate the derived key, with the
    # ciphertext
    ciphertext = salt + ciphertext
    return ciphertext


def unwrap_key_owner(passphrase, wrapped_key_ciphertext):
    iterations = 10000
    dklen = 32
    salt = wrapped_key_ciphertext[:16]

    derived_key = hashlib.pbkdf2_hmac("sha512", passphrase, salt, iterations,
                                      dklen)

    siv = SIV(derived_key)
    data_key = siv.open(wrapped_key_ciphertext[16:])
    return data_key
