from pkcs7 import pad_pkcs7
from pkcs7 import unpad_pkcs7
from Crypto.Cipher import AES
from ECB_Bytewise_Simple import GetData
from base64 import b64decode
from CBC import AES_CBC_Decrypt
from Crypto.Util.Padding import unpad
from base64 import b64encode
from functools import reduce

def EncodeString(arb_str, blocksize):

    #Quote out the characters ; and = and convert to bytes
    arb_str = arb_str.replace(";","")
    arb_str = arb_str.replace("=","")
    arb_str = bytes(arb_str, "utf-8")

    #Append the nonsense
    arb_str = b"comment1=cooking%20MCs;userdata=" + arb_str + b";comment2=%20like%20a%20pound%20of%20bacon"

    #Pad the string
    arb_str = pad_pkcs7(arb_str,16)

    #Get random key and create cipher
    key = GetData("key.txt").encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00"*16)

    #Encrypt
    ciphertext = cipher.encrypt(arb_str)

    return ciphertext

def CheckAdmin(ciphertext):
    key = GetData("key.txt").encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv=b"\x00"*16)
    pt = unpad_pkcs7(cipher.decrypt(ciphertext), 16)
    print(pt)

    return b";admin=true;" in pt

str = ">admin>true"
ct = EncodeString(str,16)

#range(0,32,16) will go from [0,32] incrementing i by 16
#Basically the same as for(i = 0; i < 32; i += 16) in C++
blocks = [ct[i:i + 16] for i in range(0, len(ct) - 16 + 1, 16)]
payload_block = blocks[1]
payload_block = list(payload_block)
payload_block[0] ^= 5
payload_block[6] ^= 3
blocks[1] = bytes(payload_block)

ct = b""
for i in range(len(blocks)):
    ct += blocks[i]

print(CheckAdmin(ct))
