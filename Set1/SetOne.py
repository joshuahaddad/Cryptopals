##Cryptopals Set One
import sys
from base64 import *
import binascii

##Problem One - Base64 > Hex and Hex > Base64
print("\nSTARTING PROBLEM 1 \n")
import base64

def From64ToHex(text):
    return base64.b64decode(text).hex()

def FromHexTo64(text):
    encoded_str = base64.b64encode(bytes.fromhex(text)).decode('utf-8')
    return encoded_str

print(FromHexTo64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")


#Problem Two - XOR
print("\nSTARTING PROBLEM 2 \n")
def HexToDecimal(text):
    return int(text, 16)

def XORHexStrings(one, two):
    one = HexToDecimal(one)
    two = HexToDecimal(two)
    return (hex(one^two))

print(XORHexStrings("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "0x746865206b696420646f6e277420706c6179")


#Problem Three - Single Char XOR
print("\nSTARTING PROBLEM 3 \n")
def SingleCharXOR(text, character):
    #ciphertext_bytes = bytes.fromhex(text)
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



value_highest = 0
best_phrase = ""
character = ""
for i in range(128):
    phrase, value = SingleCharXOR(bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"), i)
    if(value_highest < value):
        character = chr(i)
        best_phrase = phrase
        value_highest = value


print(best_phrase)
print(character)


#Problem 4 - Detecting single char xor

print("\nSTARTING PROBLEM 4 \n")

#Define variables and open file
value_highest = 0
best_phrase = ""
line_counter = 0
with open('4.txt') as fin:

    #Read each line
    for line in fin:
        #For each ASCII character, compute the single char XOR
        for i in range(128):

            #Compute XOR
            phrase, value = SingleCharXOR(bytes.fromhex(line), i)

            #Check if the value is the highest
            if(value_highest < value):

                #Format string to look pretty
                best_phrase = phrase + "ON LINE {} \nXORED AGAINST: {}" \
                    .format(line_counter, chr(i))
                value_highest = value


        #Increment the line
        line_counter += 1

#Print the found string
print(best_phrase)


#Problem 5 - Repeating XOR
print("\nSTARTING PROBLEM 5\n")

#Credit: https://github.com/JesseEmond/matasano-cryptopals/blob/master/src/xor.py
#Mine was a lot messier and buggy
def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def RepeatingXOR(text, key):
    repeats, leftover = divmod(len(text), len(key))
    return xor_bytes(text, bytes(key * repeats + key[:leftover]))


print(RepeatingXOR(b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", b'ICE').hex())


#Problem 6 - Break repeating key XOR

print("\nSTARTING PROBLEM 7\n")
def Hamming(str1, str2):
    distance = 0

    #Create iterables using zip(), stops when shortest iterable is exhausted
    for b1, b2 in zip(str1, str2):
        #XOR b1 and b2
        diff = b1 ^ b2

        #Count the ones
        distance += sum([1 for bit in bin(diff) if bit == '1'])

    return(distance)
print(Hamming(b"this is a test", b"wokka wokka!!!"))
def Crack(ciphertext, keysize):
    distances = []

    #convert to bytes
    ciphertext = base64.b64decode(ciphertext).hex()

    #Separate into blocks of size KEYSIZE
    chunks = [ciphertext[i:i+keysize] for i in range(0,len(ciphertext),keysize)]

    while True:
        try:
            #Take the first two chunks and compute the hamming distance
            str1 = chunks[0]
            str2 = chunks[1]
            dist = Hamming(bytes(str1, 'utf-8'), bytes(str2, 'utf-8'))

            #Normalize the distance and delete the chunks
            distances.append(dist/keysize)
            del chunks[0]
            del chunks[1]

        #Once there are no more blocks, return the normalized distances
        except Exception as e:
            return sum(distances)/len(distances)

#GET KEYSIZE
f = open("prob6text.txt", "r")
ciphertext = f.read()

keysize = 0
shortest = 600
for i in range(2,35):
    hamming_distance = Crack(ciphertext, i)

    if(hamming_distance < shortest):
        shortest = hamming_distance
        keysize = i

print("KEYSIZE: {}".format(keysize))

#TRANSPOSE BLOCKS
ciphertext = b64decode(ciphertext)
blocks = [ciphertext[keysize*i:keysize*(i+1)] for i in range(int(len(ciphertext)/keysize))]

chunks = []

for i in range(keysize):
    chunk = b''
    for block in blocks:
        chunk = chunk + block[i:i+1]
    chunks.append(chunk)

key = ""
a = 0
best_phrase = ""

for chunk in chunks:
    value_highest = 0
    for i in range(256):
        phrase, value = SingleCharXOR(chunk, i)
        if(value > value_highest):
            value_highest = value
            a = i
    key += chr(a)

print("KEY: {}".format(key))
print(RepeatingXOR(ciphertext, bytes(key, 'utf-8')).decode('ascii'))

#PROBLEM 7 - AES In ECB Mode
print("\nSTARTING PROBLEM 7\n")

from Crypto.Cipher import AES

def AES_ECB_Decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    return(cipher.decrypt(ciphertext))


AES_ECB_Key = b"YELLOW SUBMARINE"
AES_Text_File = open("prob7text.txt", "r")
AES_Ciphertext = b64decode(AES_Text_File.read())

print(AES_ECB_Decrypt(AES_ECB_Key, AES_Ciphertext).decode('utf8'))

#PROBLEM 8 - Detecting AES in ECB mode
print("\nSTARTING PROBLEM 8\n")


prob8_lines = [bytes.fromhex(line.strip()) for line in open("prob8.txt")]


highest_duplicates = 0
line_counter = 0
AES_Cipher = b""

with open('8.txt') as fin:
    for line in fin:

        line_counter += 1
        ECB, duplicates = Is_ECB(line)

        if(ECB):
            AES_cipher = line
            highest_duplicates = duplicates
            line_number = line_counter
            break

print("CIPHER: {}\nNUMBER: {}\nLINE:{}".format(binascii.hexlify(AES_cipher), highest_duplicates, line_number))

#END SET ONE
