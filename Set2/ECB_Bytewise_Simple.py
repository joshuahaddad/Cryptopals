from cryptopals_one import AES_ECB_Decrypt
from cryptopals_one import AES_ECB_Encrypt
from Random_AES import Generate_Key
from AES_CBC_ECB_Detection import Is_ECB
from Crypto.Util.Padding import pad
import base64
import random

def StoreKey():
    f= open("key.txt","w+")
    key = Generate_Key()
    f.write(key.decode())

def GetData(filepath):
    f = open(filepath, "r")
    return f.read()

def GenerateDictionary(blocksize, key, plaintext):
    byte_dictionary = {}

    for i in range(127):
        #Create the block such as "AAAAAAAAAB"
        plaintext += chr(65).encode() * (blocksize-1) + chr(i).encode()

        #Encrypt the data
        ciphertext = AES_ECB_Encrypt(plaintext, key)

        #Break the data into an array of bytes
        bytes = [ciphertext[i:i+2] for i in range(0,len(ciphertext),2)]

        #Take the last byte and add it to the dictionary
        byte_dictionary[bytes[len(bytes)-1]] = chr(i)

    return (byte_dictionary)

def CrackCiphertext(key, blocksize, plaintext, payload):
    dictionary = GenerateDictionary(blocksize, key, payload)
    word = ""
    for byte in plaintext:
        payload += chr(65).encode() * (blocksize-1) + bytes([byte])
        ciphertext = AES_ECB_Encrypt(payload, key)
        byte_array = [ciphertext[i:i+2] for i in range(0,len(ciphertext),2)]
        word += (dictionary[byte_array[len(byte_array)-1]])
    print(word)

#key = GetData("key.txt").encode('utf-8')
#plaintext = base64.b64decode(GetData("12.txt"))
#blocksize = 16
#payload = b""

#CrackCiphertext(key, blocksize, plaintext, payload)
#dictionary = GenerateDictionary(blocksize, key)

#word = ""
#print(dictionary)
#for byte in plaintext:
#    payload = chr(65).encode() * (blocksize-1) + bytes([byte])
#    ciphertext = AES_ECB_Encrypt(payload, key)
#    byte_array = [ciphertext[i:i+2] for i in range(0,len(ciphertext),2)]
#    word += (dictionary[byte_array[len(byte_array)-1]])

#print(word)
