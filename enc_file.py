# Used for encrypting the files to be uploaded to dataverse
from miscreant.aes.siv import SIV
import os


def enc_file(filepath):
    key = SIV.generate_key()
    siv = SIV(key)
    nonce = os.urandom(16)

    with open(filepath, 'r') as myfile:
        data = myfile.read()
        ciphertext = siv.seal(data, [nonce])
        return (key, nonce + ciphertext)
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

