def pad_pkcs7(text, blocksize):
    padding = blocksize - len(text) % blocksize
    for i in range(padding):
        text += bytes(chr(padding),'utf-8')
    return text

def unpad_pkcs7(text, blocksize):

    #Padding should produce a string divisible by 16
    if len(text) % blocksize != 0:
        raise IncorrectPadding

    last_byte = text[-1]
    if text.endswith(bytes([last_byte])*last_byte):
        return text[:-last_byte]
    else:
        raise IncorrectPadding
