from Random_AES import *
from cryptopals_one_functions import Is_ECB

def Detect_AES(plaintext):
    ciphertext, type = Random_Encrypt(plaintext)
    ECB, duplicates = Is_ECB(ciphertext)

    #If both true or both false
    if((ECB and type) or (not ECB and not type)):
        return 0

    #If ECB is true but type is CBC (false)
    if(ECB and not type):
        return 1

    #If ECB is false but type is true
    if(not ECB and type):
        return 2

def Attempt_Detection(trials):
    plaintext = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    count = [0,0,0]

    for i in range(int(trials)):
        count[Detect_AES(plaintext)] += 1

    print("SUCCESS: {} \nDETECTED-WRONG: {}\nNOT-DETECTED:{}".format(count[0], count[1], count[2]))
    print("SUCCESS: {} \nFAILURE: {} \nTRIALS:{} \nPERCENT:{}%".format(count[0], trials-count[0], trials, count[0]/trials*100))

Attempt_Detection(100)
