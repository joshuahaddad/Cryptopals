import sys
from base64 import *
import binascii
from Crypto.Cipher import AES

def From64ToHex(text):
    return base64.b64decode(text).hex()

def FromHexTo64(text):
    encoded_str = base64.b64encode(bytes.fromhex(text)).decode('utf-8')
    return encoded_str

def HexToDecimal(text):
    return int(text, 16)

def XORHexStrings(one, two):
    one = HexToDecimal(one)
    two = HexToDecimal(two)
    return (hex(one^two))

def SingleCharXOR(text, character):
    ciphertext_bytes = text

    word = ""
    frequency = 0

    for byte in ciphertext_bytes:
        word += chr(byte ^ character)
        frequency += GetScore(byte ^ character)

    return word, frequency

def GetScore(char):
    if(char > 64 and char < 90):
        char += 32

    frequency = {
        'a': 8.167, 'b': 1.492, 'c': 2.782, 'd': 4.253, 'e': 12.702,
        'f': 2.228, 'g': 2.015, 'h': 6.094, 'i': 6.966, 'j': 0.153,
        'k': 0.772, 'l': 4.025, 'm': 2.406, 'n': 6.749, 'o': 7.507,
        'p': 1.929, 'q': 0.095, 'r': 5.987, 's': 6.327, 't': 9.056,
        'u': 2.758, 'v': 0.978, 'w': 2.360, 'x': 0.150, 'y': 1.974,
        'z': 0.074, ' ': 12.8
    }

    return frequency.get(chr(char), 0)

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def RepeatingXOR(text, key):
    repeats, leftover = divmod(len(text), len(key))
    return xor_bytes(text, bytes(key * repeats + key[:leftover]))

def Hamming(str1, str2):
    distance = 0

    #Create iterables using zip(), stops when shortest iterable is exhausted
    for b1, b2 in zip(str1, str2):
        #XOR the strings
        diff = b1 ^ b2

        #Count the ones
        distance += sum([1 for bit in bin(diff) if bit == '1'])

    return(distance)

def Crack(ciphertext, keysize):
    distances = []

    #convert to bytes
    ciphertext = base64.b64decode(ciphertext).hex()

    chunks = [ciphertext[i:i+keysize] for i in range(0,len(ciphertext),keysize)]

    while True:
        try:
            str1 = chunks[0]
            str2 = chunks[1]
            dist = Hamming(bytes(str1, 'utf-8'), bytes(str2, 'utf-8'))
            distances.append(dist/keysize)
            del chunks[0]
            del chunks[1]
        except Exception as e:
            return sum(distances)/len(distances)


    distance = Hamming(str1,str2,16)
    print(distance)
    return(distance/keysize)

def AES_ECB_Decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return(cipher.decrypt(ciphertext))

def AES_ECB_Encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return(cipher.encrypt(plaintext))

def Is_ECB(ciphertext):
    chunks = [ciphertext[i*16:(i+1)*16] for i in range(int(len(ciphertext)/16))]
    highest_duplicates = 0

    duplicates = len(chunks) - len(set(chunks))


    if(duplicates >= 1):
        return True, duplicates
    else:
        return False, 0
