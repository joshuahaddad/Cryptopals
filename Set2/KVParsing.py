from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from ECB_Bytewise_Simple import GetData
from AES_CBC_ECB_Detection import Is_ECB
from pks7 import pkcs7

counter = 0

def CreateToken(text):
    words = text.split('&')
    dictionary = {}
    for word in words:
        data = word.split('=')
        dictionary[data[0]] = data[1]

    return(dictionary)

def ProfileFor(username):
    username = username.replace("&","")
    username = username.replace("=","")

    global counter
    token_string = "email={}&uid={}&role=user".format(username, counter)
    return CreateToken(token_string)

def EncodeToken(token):
    return "email={}&uid={}&role={}".format(token["email"],token["uid"],token["role"])

def EncryptToken(token, key):
    plaintext = bytes(token, 'utf-8')
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))

def DecryptToken(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return unpad(plaintext, AES.block_size)


def CrackOracle(key):
    str = ""
    for i in range(2):
        if(i==0):
            #Feed foo@bar.couser first to isolate the "user" block
            token = EncodeToken(ProfileFor("malware@bar.co"))
            enc_token = EncryptToken(token, key).hex()
        if(i==1):
            payload = "foo@bar.co" + pkcs7(b"admin",16).decode()
            token = EncodeToken(ProfileFor(payload))
            enc_token = EncryptToken(token, key).hex()

        blocks = [enc_token[i*32:(i+1)*32] for i in range(int(len(enc_token)/32))]

        if(i==0):
            str += blocks[0]+blocks[1]
        if(i==1):
            str += blocks[1]
    print(DecryptToken(bytes.fromhex(str), key))

key = GetData("key.txt").encode('utf-8')
CrackOracle(key)
