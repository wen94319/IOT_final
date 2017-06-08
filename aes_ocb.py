from ocb.aes import AES
from ocb import OCB
import sys


class AES_cipher:
    def __init__(self):
        self.en_nonce = bytearray(range(16))
        self.de_nonce = bytearray(range(16))
        self.key = bytearray().fromhex('A45F5FDEA5C088D1D7C8BE37CABC8C5C')
        self.aes = AES(128)
        self.ocb = OCB(self.aes)
        self.ocb.setKey(self.key)

    def Encrypt(self, plaintext, header):
        self.ocb.setNonce(self.en_nonce)
        plaintext = bytearray(plaintext)
        header = bytearray(header)
        (tag, ciphertext) = self.ocb.encrypt(plaintext, header)
        return (tag, ciphertext)

    def Decrypt(self, ciphertext, header, tag):
        self.ocb.setNonce(self.de_nonce)
        ciphertext = bytearray(ciphertext)
        header = bytearray(header)
        tag = bytearray(tag)
        (is_authentic, plaintext) = self.ocb.decrypt(header, ciphertext, tag)
        plaintext = plaintext.decode('utf-8')
        return (is_authentic, plaintext)

# if __name__ == '__main__':
#   if len(sys.argv) < 3:
#       print('Usage: \n python final.py <Your Message to be encrypt> <Authencation Associated String>')
#       sys.exit()
#
#   Message = sys.argv[1]
#   Auth = sys.argv[2]
#   test = AES_cipher(Message,Auth);
#   (is_authentic, results) = test.AES_Cypher()
#   print "Is authentic ?: "+ str(is_authentic)
#   print "Decryption : " + results
