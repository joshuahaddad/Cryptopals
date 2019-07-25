from Crypto.Cipher import AES
import random
from Crypto.Util.Padding import pad


#If it is ECB, we can detect by comparing each plaintext block to other blocks.
#If there are repeated blocks, that is easy indication that it is ECB since
#each identical block will be encoded the same

#Rand numbers = random.randint(0,1) for [0,1]

def Choose_AES(key):
    choice = random.randint(0,1)
    if(choice == 0):
        return AES.new(key, AES.MODE_ECB), True
    if(choice == 1):
        return AES.new(key, AES.MODE_CBC), False

def Append_Bytes(plaintext):
    before = random.randint(5,10)
    after = random.randint(5,10)

    new_bytes = b""
    for i in range(before):
        new_bytes += bytes(chr(random.randint(0,255)), 'utf-8')

    new_bytes += plaintext

    for i in range(after):
        new_bytes += bytes(chr(random.randint(0,255)), 'utf-8')

    return new_bytes

def Generate_Key():
    key = b""

    for i in range(16):
        key += bytes(chr(random.randint(64,126)), 'utf-8')

    return key

def Random_Encrypt(plaintext):
    key = Generate_Key()
    cipher, type = Choose_AES(key)
    plaintext = Append_Bytes(plaintext)
    ciphertext = cipher.encrypt(pad(plaintext, 16))
    return ciphertext, type
