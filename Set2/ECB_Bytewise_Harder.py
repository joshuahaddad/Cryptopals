from ECB_Bytewise_Simple import GetData
from ECB_Bytewise_Simple import CrackCiphertext
from cryptopals_one import AES_ECB_Decrypt
from cryptopals_one import AES_ECB_Encrypt
from AES_CBC_ECB_Detection import Is_ECB
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import base64
import random

def AddPrefix(plaintext):
    new_plaintext = b""
    for i in range(random.randint(1,20)):
        new_plaintext += bytes([random.randint(33,126)])

    return new_plaintext + plaintext


key = GetData("key.txt").encode('utf-8')
plaintext = base64.b64decode(GetData("12.txt"))
blocksize = 16
payload = AddPrefix(b"")
Found_ECB = False

#First, generate a payload which is correctly detected as AES_ECB
#Since ECB is detected if two blocks are duplicate, this will produce a payload
#Which is length % 16 = 0 (IE whole number of blocks) and allow us to control final block

ciphertext = b""
while(not Is_ECB(ciphertext)):
    ciphertext = b""
    payload += b"A"
    ciphertext = AES_ECB_Encrypt(pad(payload,16), key)

#Solve the problem exactly like problem 12
CrackCiphertext(key, blocksize, plaintext, payload)

#Craft a string of blocks like AAAAAAAAAA AAAAAAAAAA AAAAAAAAAB
#Detect ECB, if detected then we can assume the padding was a multiple of 16
#Get the last byte of the encrypted data and add to a dictionary
#Once you have the ascii characters, repeat for each byte in the plaintext
ECB_ciphertext = b""
idx = 0
byte_dictionary = {}

while (idx < 126):
    while (not Is_ECB(ECB_ciphertext) or len(payload) % 16 != 0):
        payload = AddPrefix(b"") + b"!$!$!$!$!$!$!$!$!$!$!$!$!$!$!$!$AAAAAAAAAAAAAAA" + bytes(chr(idx), 'utf-8')
        ECB_ciphertext = AES_ECB_Encrypt(pad(payload,16), key)

    hex_cipher = ECB_ciphertext.hex()
    hex_array = [hex_cipher[i*32:(i+1)*32] for i in range(int(len(hex_cipher)/32))]
    interesting_block = hex_array[len(hex_array)-2]
    byte_dictionary[interesting_block] = chr(idx)
    ECB_ciphertext = b""
    idx += 1

word = ""
for byte in plaintext:
    while (not Is_ECB(ECB_ciphertext) or len(payload) % 16 != 0):
        payload = AddPrefix(b"") + b"!$!$!$!$!$!$!$!$!$!$!$!$!$!$!$!$AAAAAAAAAAAAAAA" + bytes([byte])
        ECB_ciphertext = AES_ECB_Encrypt(pad(payload,16), key)

    hex_cipher = ECB_ciphertext.hex()
    hex_array = [hex_cipher[i*32:(i+1)*32] for i in range(int(len(hex_cipher)/32))]
    interesting_block = hex_array[len(hex_array)-2]
    character = bytes.fromhex(interesting_block[30:32])

    word += (byte_dictionary[interesting_block])
    ECB_ciphertext = b""

print(word)
