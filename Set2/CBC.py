from cryptopals_one import AES_ECB_Decrypt
from cryptopals_one import AES_ECB_Encrypt
from cryptopals_one import xor_bytes
from base64 import *

def AES_CBC_Decrypt(ciphertext, key):
    keysize = len(key)
    blocks = [ciphertext[i*keysize:(i+1)*keysize] for i in range(int(len(ciphertext)/keysize))]

    IV = chr(0).encode() * keysize
    last_block = IV
    plaintext = ""

    for block in blocks:
        AES_Decrypted = AES_ECB_Decrypt(block, key)
        plaintext += xor_bytes(AES_Decrypted, last_block).decode()
        last_block = block

    return plaintext


    
