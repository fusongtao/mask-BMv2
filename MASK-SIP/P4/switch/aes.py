import hashlib
import hmac
import struct
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex




def add_to_16(text):
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')


# '9999999999999999'
def encrypt(text,key):
    #key = pack_128(k)  #(str(k)).encode('utf-8')
    print(key)
    mode = AES.MODE_CBC
    iv = b'qqqqqqqqqqqqqqqq'
    text = add_to_16(text)
    cryptos = AES.new(key, mode, iv)
    cipher_text = cryptos.encrypt(text)    #16
    return b2a_hex(cipher_text)





if __name__ == '__main__':
    main()
